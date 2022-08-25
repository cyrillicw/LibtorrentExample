#include <vector>
#include <filesystem>
#include <fstream>
#include <cstring>
#include <iostream>
#include <string>

// libtorrent
#include <libtorrent/alert.hpp>
#include <libtorrent/alert_types.hpp>
#include <libtorrent/session.hpp>
#include <libtorrent/magnet_uri.hpp>
#include <libtorrent/hex.hpp>
#include <libtorrent/create_torrent.hpp>
#include <libtorrent/torrent_flags.hpp>
#include <libtorrent/torrent.hpp>
#include <libtorrent/extensions/ut_metadata.hpp>
#include "libtorrent/aux_/session_impl.hpp"
#include "libtorrent/extensions.hpp"
#include "libtorrent/socket.hpp"

namespace lt = libtorrent;
namespace fs = std::filesystem;
using lt_handle = lt::torrent_handle;
std::atomic<int> done = 0;

void generate_random_file(uint size, std::string folder, std::string name) {
    std::filesystem::create_directories(folder);
    std::fstream f(folder + "/" + name, std::fstream::out | std::fstream::binary);
    for (uint i = 0; i < size; i++) {
        f << static_cast<char>(rand());
    }
    f.close();
}

class DefaultSession : std::enable_shared_from_this<DefaultSession> {

private:

    // Endpoint of libtorrent node
    //
    std::string m_addressAndPort;

    // Libtorrent session
    //
    lt::session m_session;

public:

    DefaultSession(std::string address
    )
    : m_addressAndPort(address) {
        createSession(false);
    }

    virtual ~DefaultSession() {
    }


    // createSession
    void createSession(bool useTcpSocket) {

        lt::settings_pack settingsPack;

        settingsPack.set_int( lt::settings_pack::alert_mask, ~0 );//lt::alert_category::all );

        // todo public_key?
        char todoPubKey[32];
        std::memset(todoPubKey,'x', sizeof(todoPubKey));
        todoPubKey[5] = 0;
        settingsPack.set_str(  lt::settings_pack::user_agent, std::string(todoPubKey,32) );

        if ( useTcpSocket )
        {
            settingsPack.set_bool( lt::settings_pack::enable_outgoing_utp, false );
            settingsPack.set_bool( lt::settings_pack::enable_incoming_utp, false );
            settingsPack.set_bool( lt::settings_pack::enable_outgoing_tcp, true );
            settingsPack.set_bool( lt::settings_pack::enable_incoming_tcp, true );
        }

        //todo 1. is it enough? 2. is it for single peer?
        settingsPack.set_int( lt::settings_pack::dht_upload_rate_limit, 8000000 );

        settingsPack.set_bool( lt::settings_pack::enable_dht, true );
        settingsPack.set_bool( lt::settings_pack::enable_lsd, false ); // is it needed?
        settingsPack.set_bool( lt::settings_pack::enable_upnp, true );

        settingsPack.set_str(  lt::settings_pack::dht_bootstrap_nodes, "");

        settingsPack.set_str(  lt::settings_pack::listen_interfaces, m_addressAndPort );
        settingsPack.set_bool( lt::settings_pack::allow_multiple_connections_per_ip, false );
        settingsPack.set_bool( lt::settings_pack::enable_ip_notifier, false );

        settingsPack.set_int( lt::settings_pack::max_retry_port_bind, 0 );
        settingsPack.set_bool( lt::settings_pack::listen_system_port_fallback, false );

        m_session.apply_settings(settingsPack);
        m_session.set_alert_notify([this] { alertHandler(); });
    }

    auto addFilesToSession(const std::string &workFolder) {

        // path to the data to be loaded into the replicator
        fs::path sandboxFolder = fs::path(workFolder);

        // create torrent file
        auto infoHash = createTorrentFile(fs::path(sandboxFolder),
                                          fs::path(sandboxFolder) / "root.torrent");

        // add torrent file
        addTorrentFileToSession(fs::path(sandboxFolder) / "root.torrent",
                                workFolder);
        return infoHash;
    }

    // downloadFile
    virtual lt_handle download(lt::info_hash_t const& hash,
                               const std::string &tmpFolder,
                               const std::vector<lt::tcp::endpoint>& peers) {

        // create add_torrent_params
        lt::error_code ec;
        lt::add_torrent_params params;
        params.info_hashes = hash;

        // where the file will be placed
        params.save_path = tmpFolder;

        // create torrent_handle
        lt::torrent_handle tHandle = m_session.add_torrent(params, ec);
        if (ec) {
            throw std::runtime_error(std::string("downloadFile error: ") + ec.message());
        }

        if (!m_session.is_valid())
            throw std::runtime_error("downloadFile: libtorrent session is not valid");

        if (!tHandle.is_valid())
            throw std::runtime_error("downloadFile: torrent handle is not valid");

        // connect to peers
        for (const auto &it : peers) {
            tHandle.connect_peer(it);
        }
        return tHandle;
    }

private:

    virtual lt_handle addTorrentFileToSession(const std::string &torrentFilename,
                                              const std::string &savePath) {

        // read torrent file
        std::ifstream torrentFile(torrentFilename);
        std::vector<char> buffer((std::istreambuf_iterator<char>(torrentFile)), std::istreambuf_iterator<char>());

        // create add_torrent_params
        lt::add_torrent_params params;
        params.flags &= ~lt::torrent_flags::paused;
        params.flags &= ~lt::torrent_flags::auto_managed;

        //todo?
        params.flags |= lt::torrent_flags::seed_mode;
//        params.flags |= lt::torrent_flags::upload_mode;
        params.flags |= lt::torrent_flags::no_verify_files;

        params.storage_mode = lt::storage_mode_sparse;
        params.save_path = fs::path(savePath);
        params.ti = std::make_shared<lt::torrent_info>(buffer, lt::from_span);

        auto tInfo = lt::torrent_info(buffer, lt::from_span);

        lt::torrent_handle tHandle = m_session.add_torrent(params);

        return tHandle;
    }

    void alertHandler() {

        // extract alerts
        std::vector<lt::alert *> alerts;
        m_session.pop_alerts(&alerts);

        // loop by alerts
        for (auto const* alert : alerts) {
            switch (alert->type()) {
//                case lt::peer_log_alert::alert_type: {
//                    std::cout << m_addressAndPort << ": peer_log_alert: " << alert->message() << std::endl;
//                    break;
//                }
                case lt::torrent_finished_alert::alert_type: {
                    std::cout << m_addressAndPort << ": torrent_finished_alert: " << alert->message() << std::endl;
                    done += 1;
                    break;
                }
            }
        }
    }

    lt::info_hash_t createTorrentFile(const std::string &fileOrFolder, const std::string &outputTorrentFilename) {
        // setup file storage
        lt::file_storage fStorage;
        lt::add_files(fStorage, fileOrFolder, lt::create_flags_t{});

        // create torrent info
        lt::create_torrent createInfo(fStorage, 64 * 1024, lt::create_torrent::v2_only);
        // calculate hashes for 'fileOrFolder' relative to 'rootFolder'
        lt::error_code ec;
        lt::set_piece_hashes(createInfo, fs::path(fileOrFolder).parent_path(), ec);
        if (ec) {
            throw std::runtime_error(std::string("createTorrentFile error: ") + ec.message());
        }

        // generate metadata
        lt::entry entry_info = createInfo.generate();

        // convert to bencoding
        std::vector<char> torrentFileBytes;
        lt::bencode(std::back_inserter(torrentFileBytes), entry_info); // metainfo -> binary

        auto entry = entry_info;
        auto tInfo = lt::torrent_info(torrentFileBytes, lt::from_span);

        // get infoHash
        lt::torrent_info torrentInfo(torrentFileBytes, lt::from_span);
        auto ret = torrentInfo.info_hashes();

        // write to file
        if (!outputTorrentFilename.empty()) {
            std::ofstream fileStream(outputTorrentFilename, std::ios::binary);
            fileStream.write(torrentFileBytes.data(), torrentFileBytes.size());
        }

        return ret;
    }
};

std::shared_ptr<DefaultSession> createDefaultSession(std::string address) {
    return std::make_shared<DefaultSession>(address);
}

class Uploader {
public:
    std::shared_ptr<DefaultSession> m_clientSession;

    Uploader(std::string address) : m_clientSession(createDefaultSession(address)) {}

    auto upload(std::string root_path, std::string file_name, uint file_size) {
        std::string uploader_path = root_path + "/" + "uploader";
        generate_random_file(file_size, uploader_path, file_name);
        return m_clientSession->addFilesToSession(uploader_path);
    }
};

class Downloader {
public:
    std::shared_ptr<DefaultSession> m_session;
    std::string m_address;

    Downloader(std::string address) : m_session(createDefaultSession(address)), m_address(address) {}

    void download(lt::info_hash_t const& hash, std::string root_path, const std::vector<lt::tcp::endpoint>& peers) {
        std::filesystem::create_directories(root_path);
        std::string downloader_path = root_path + "/" + "downloader";
        m_session->download(hash, downloader_path, peers);
    }
};

int main() {
    // prepare for testing
    std::string root_folder = fs::path(".") / "111";
    std::filesystem::remove_all(root_folder);
    std::filesystem::create_directories(root_folder);

    std::string uploader_ip = "192.168.2.200";
    unsigned short uploader_port = 5000;
    std::string uploader_address = uploader_ip + ":" + std::to_string(uploader_port);
    Uploader uploader(uploader_address);

    auto hash = uploader.upload(root_folder + "/" + std::to_string(rand()), "b.bin", 1024 * 1024 * 1024);

    std::vector<Downloader> downloaders;

    std::vector<std::string> downloaders_ip = {"192.168.2.101", "192.168.2.102", "192.168.2.103", "192.168.2.104", "192.168.2.105"};
    uint16_t downloader_port = 5001;

    std::vector<lt::tcp::endpoint> points = {{boost::asio::ip::address::from_string(uploader_ip), uploader_port}};

    for ( int i = 0; i < 5; i++ ) {
        downloaders.emplace_back( downloaders_ip[i] + ":" + std::to_string(downloader_port) );
        points.emplace_back(boost::asio::ip::address::from_string(downloaders_ip[i]), downloader_port);
    }

    for( uint i = 0; i < downloaders.size(); i++ ) {
        auto& downloader = downloaders[i];
        auto bootstraps = points;
        bootstraps.erase(bootstraps.begin() + i + 1);
        downloader.download(hash, root_folder + "/" + downloader.m_address, bootstraps);
    }

    int total = downloaders.size() + 1;
    while (done < total) {
        using namespace std::chrono_literals;
        std::this_thread::sleep_for(1s);
    }
}
