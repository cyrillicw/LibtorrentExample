#include <vector>
#include <filesystem>
#include <fstream>
#include <cstring>
#include <iostream>

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

static char byteMap[256][2] = {
        {'0', '0'},
        {'0', '1'},
        {'0', '2'},
        {'0', '3'},
        {'0', '4'},
        {'0', '5'},
        {'0', '6'},
        {'0', '7'},
        {'0', '8'},
        {'0', '9'},
        {'0', 'a'},
        {'0', 'b'},
        {'0', 'c'},
        {'0', 'd'},
        {'0', 'e'},
        {'0', 'f'},
        {'1', '0'},
        {'1', '1'},
        {'1', '2'},
        {'1', '3'},
        {'1', '4'},
        {'1', '5'},
        {'1', '6'},
        {'1', '7'},
        {'1', '8'},
        {'1', '9'},
        {'1', 'a'},
        {'1', 'b'},
        {'1', 'c'},
        {'1', 'd'},
        {'1', 'e'},
        {'1', 'f'},
        {'2', '0'},
        {'2', '1'},
        {'2', '2'},
        {'2', '3'},
        {'2', '4'},
        {'2', '5'},
        {'2', '6'},
        {'2', '7'},
        {'2', '8'},
        {'2', '9'},
        {'2', 'a'},
        {'2', 'b'},
        {'2', 'c'},
        {'2', 'd'},
        {'2', 'e'},
        {'2', 'f'},
        {'3', '0'},
        {'3', '1'},
        {'3', '2'},
        {'3', '3'},
        {'3', '4'},
        {'3', '5'},
        {'3', '6'},
        {'3', '7'},
        {'3', '8'},
        {'3', '9'},
        {'3', 'a'},
        {'3', 'b'},
        {'3', 'c'},
        {'3', 'd'},
        {'3', 'e'},
        {'3', 'f'},
        {'4', '0'},
        {'4', '1'},
        {'4', '2'},
        {'4', '3'},
        {'4', '4'},
        {'4', '5'},
        {'4', '6'},
        {'4', '7'},
        {'4', '8'},
        {'4', '9'},
        {'4', 'a'},
        {'4', 'b'},
        {'4', 'c'},
        {'4', 'd'},
        {'4', 'e'},
        {'4', 'f'},
        {'5', '0'},
        {'5', '1'},
        {'5', '2'},
        {'5', '3'},
        {'5', '4'},
        {'5', '5'},
        {'5', '6'},
        {'5', '7'},
        {'5', '8'},
        {'5', '9'},
        {'5', 'a'},
        {'5', 'b'},
        {'5', 'c'},
        {'5', 'd'},
        {'5', 'e'},
        {'5', 'f'},
        {'6', '0'},
        {'6', '1'},
        {'6', '2'},
        {'6', '3'},
        {'6', '4'},
        {'6', '5'},
        {'6', '6'},
        {'6', '7'},
        {'6', '8'},
        {'6', '9'},
        {'6', 'a'},
        {'6', 'b'},
        {'6', 'c'},
        {'6', 'd'},
        {'6', 'e'},
        {'6', 'f'},
        {'7', '0'},
        {'7', '1'},
        {'7', '2'},
        {'7', '3'},
        {'7', '4'},
        {'7', '5'},
        {'7', '6'},
        {'7', '7'},
        {'7', '8'},
        {'7', '9'},
        {'7', 'a'},
        {'7', 'b'},
        {'7', 'c'},
        {'7', 'd'},
        {'7', 'e'},
        {'7', 'f'},
        {'8', '0'},
        {'8', '1'},
        {'8', '2'},
        {'8', '3'},
        {'8', '4'},
        {'8', '5'},
        {'8', '6'},
        {'8', '7'},
        {'8', '8'},
        {'8', '9'},
        {'8', 'a'},
        {'8', 'b'},
        {'8', 'c'},
        {'8', 'd'},
        {'8', 'e'},
        {'8', 'f'},
        {'9', '0'},
        {'9', '1'},
        {'9', '2'},
        {'9', '3'},
        {'9', '4'},
        {'9', '5'},
        {'9', '6'},
        {'9', '7'},
        {'9', '8'},
        {'9', '9'},
        {'9', 'a'},
        {'9', 'b'},
        {'9', 'c'},
        {'9', 'd'},
        {'9', 'e'},
        {'9', 'f'},
        {'a', '0'},
        {'a', '1'},
        {'a', '2'},
        {'a', '3'},
        {'a', '4'},
        {'a', '5'},
        {'a', '6'},
        {'a', '7'},
        {'a', '8'},
        {'a', '9'},
        {'a', 'a'},
        {'a', 'b'},
        {'a', 'c'},
        {'a', 'd'},
        {'a', 'e'},
        {'a', 'f'},
        {'b', '0'},
        {'b', '1'},
        {'b', '2'},
        {'b', '3'},
        {'b', '4'},
        {'b', '5'},
        {'b', '6'},
        {'b', '7'},
        {'b', '8'},
        {'b', '9'},
        {'b', 'a'},
        {'b', 'b'},
        {'b', 'c'},
        {'b', 'd'},
        {'b', 'e'},
        {'b', 'f'},
        {'c', '0'},
        {'c', '1'},
        {'c', '2'},
        {'c', '3'},
        {'c', '4'},
        {'c', '5'},
        {'c', '6'},
        {'c', '7'},
        {'c', '8'},
        {'c', '9'},
        {'c', 'a'},
        {'c', 'b'},
        {'c', 'c'},
        {'c', 'd'},
        {'c', 'e'},
        {'c', 'f'},
        {'d', '0'},
        {'d', '1'},
        {'d', '2'},
        {'d', '3'},
        {'d', '4'},
        {'d', '5'},
        {'d', '6'},
        {'d', '7'},
        {'d', '8'},
        {'d', '9'},
        {'d', 'a'},
        {'d', 'b'},
        {'d', 'c'},
        {'d', 'd'},
        {'d', 'e'},
        {'d', 'f'},
        {'e', '0'},
        {'e', '1'},
        {'e', '2'},
        {'e', '3'},
        {'e', '4'},
        {'e', '5'},
        {'e', '6'},
        {'e', '7'},
        {'e', '8'},
        {'e', '9'},
        {'e', 'a'},
        {'e', 'b'},
        {'e', 'c'},
        {'e', 'd'},
        {'e', 'e'},
        {'e', 'f'},
        {'f', '0'},
        {'f', '1'},
        {'f', '2'},
        {'f', '3'},
        {'f', '4'},
        {'f', '5'},
        {'f', '6'},
        {'f', '7'},
        {'f', '8'},
        {'f', '9'},
        {'f', 'a'},
        {'f', 'b'},
        {'f', 'c'},
        {'f', 'd'},
        {'f', 'e'},
        {'f', 'f'},
        };

std::string magnetLink(const std::string &key) {

    char hashStr[64 + 1];

    for (uint32_t i = 0; i < 32; i++) {
        uint8_t v = key[i];
        hashStr[2 * i] = byteMap[v][0];
        hashStr[2 * i + 1] = byteMap[v][1];
    }
    hashStr[64] = 0;

    return std::string("magnet:?xt=urn:btmh:1220") + std::string(hashStr, hashStr + 64);
}

void generate_random_file(uint size, std::string folder, std::string name) {
    std::filesystem::create_directories(folder);
    std::fstream f(folder + "/" + name, std::fstream::out | std::fstream::binary);
    for (uint i = 0; i < size; i++) {
        f << static_cast<char>(rand());
    }
    f.close();
}

std::fstream logger;

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

        settingsPack.set_int(lt::settings_pack::alert_mask, ~0);//lt::alert_category::all );
        settingsPack.set_str(lt::settings_pack::dht_bootstrap_nodes, "");

        // todo public_key?
        char todoPubKey[32];
        std::memset(todoPubKey, 'x', sizeof(todoPubKey));
        todoPubKey[5] = 0;
        settingsPack.set_str(lt::settings_pack::user_agent, std::string(todoPubKey, 32));

        if (useTcpSocket) {
            settingsPack.set_bool(lt::settings_pack::enable_outgoing_utp, false);
            settingsPack.set_bool(lt::settings_pack::enable_incoming_utp, false);
            settingsPack.set_bool(lt::settings_pack::enable_outgoing_tcp, true);
            settingsPack.set_bool(lt::settings_pack::enable_incoming_tcp, true);
        }

        settingsPack.set_int(lt::settings_pack::dht_upload_rate_limit, 8000000);

        settingsPack.set_bool(lt::settings_pack::enable_dht, true);
        settingsPack.set_bool(lt::settings_pack::enable_lsd, false); // is it needed?
        settingsPack.set_bool(lt::settings_pack::enable_upnp, false);
        settingsPack.set_str(lt::settings_pack::dht_bootstrap_nodes, "");

        settingsPack.set_str(lt::settings_pack::listen_interfaces, m_addressAndPort);
        settingsPack.set_bool(lt::settings_pack::allow_multiple_connections_per_ip, false);

        m_session.apply_settings(settingsPack);
        m_session.set_alert_notify([this] { alertHandler(); });
    }

    auto addFilesToSession(const std::string &workFolder) {

        // path to the data to be loaded into the replicator
        fs::path sandboxFolder = fs::path(workFolder);

        // create torrent file
        auto infoHash = createTorrentFile(fs::path(sandboxFolder), workFolder,
                                          fs::path(sandboxFolder) / "root.torrent");

        // add torrent file
        addTorrentFileToSession(fs::path(sandboxFolder) / "root.torrent",
                                workFolder);
        return infoHash;
    }

    // downloadFile
    virtual lt_handle download(const std::string &hash,
                               const std::string &tmpFolder,
                               const std::vector<lt::tcp::endpoint>& peers) {

        // create add_torrent_params
        lt::error_code ec;
        lt::add_torrent_params params = lt::parse_magnet_uri(magnetLink(hash), ec);
        if (ec) {
            throw std::runtime_error(std::string("downloadFile error: ") + ec.message());
        }

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
        params.flags |= lt::torrent_flags::upload_mode;
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
        for (auto &alert : alerts) {
            switch (alert->type()) {
                case lt::peer_log_alert::alert_type: {
                    logger << m_addressAndPort << ": peer_log_alert: " << alert->message() << std::endl;
                    break;
                }
                case lt::torrent_log_alert::alert_type: {
                    logger << m_addressAndPort << ": torrent_log_alert: " << alert->message() << std::endl;
                    break;
                }
            }
        }
    }

    std::string createTorrentFile(const std::string &fileOrFolder, const std::string &rootFolder,
                                  const std::string &outputTorrentFilename) {
        // setup file storage
        lt::file_storage fStorage;
        lt::add_files(fStorage, fileOrFolder, lt::create_flags_t{});

        // create torrent info
        lt::create_torrent createInfo(fStorage, 16 * 1024, lt::create_torrent::v2_only);
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
        auto binaryString = torrentInfo.info_hashes().v2.to_string();

        // write to file
        if (!outputTorrentFilename.empty()) {
            std::ofstream fileStream(outputTorrentFilename, std::ios::binary);
            fileStream.write(torrentFileBytes.data(), torrentFileBytes.size());
        }

        return binaryString;
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

    Downloader(std::string address) : m_session(createDefaultSession(address)) {}

    void download(std::string hash, std::string root_path, const std::vector<lt::tcp::endpoint>& peers) {
        std::string downloader_path = root_path + "/" + "downloader";
        m_session->download(hash, downloader_path, peers);
    }
};

int main() {
    // prepare for testing
    std::string root_folder = fs::path(getenv("HOME")) / "111";
    std::filesystem::remove_all(root_folder);
    std::filesystem::create_directories(root_folder);
    logger.open(root_folder + "/log.txt", std::fstream::out);

    std::string uploader_ip = "127.0.0.1";
    unsigned short uploader_port = 5000;
    std::string uploader_address = uploader_ip + ":" + std::to_string(uploader_port);
    Uploader uploader(uploader_address);

    std::string downloader_address = "127.0.0.1:5001";
    Downloader downloader(downloader_address);

    auto hash = uploader.upload(root_folder, "b.bin", 100 * 1024 * 1024);

    std::vector<lt::tcp::endpoint> points = {{boost::asio::ip::address::from_string(uploader_ip), uploader_port}};
    downloader.download(hash, root_folder, points);

    int wait;
    std::cin >> wait;
    logger.flush();
    logger.close();
}
