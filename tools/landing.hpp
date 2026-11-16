/**
 *  @file tools/landing.hpp
 *  @author Ash Vardanian
 *  @date November 16, 2026
 *  @brief Files the command line writes through a temporary beside the target, landed over it
 *      only once whole.
 */
#pragma once

#include <cstddef> // `std::size_t`
#include <cstdio>  // `std::FILE`, `std::fflush`, `std::fclose`, `std::remove`
#include <cstring> // `std::memcpy`, `std::strlen`, `std::strrchr`

#include "ucall/utilities/types.hpp" // `UCALL_OS_WINDOWS_`

#if UCALL_OS_WINDOWS_
#include <fcntl.h>    // `_O_CREAT`, `_O_EXCL`, `_O_WRONLY`, `_O_BINARY`
#include <io.h>       // `_open`, `_commit`, `_close`
#include <sys/stat.h> // `_S_IREAD`, `_S_IWRITE`
#include <winsock2.h> // ahead of <windows.h>, which would drag in Winsock 1.1
#include <windows.h>  // `MoveFileExA`
#else
#include <fcntl.h>  // `open`, `O_NOFOLLOW`, `O_EXCL`
#include <unistd.h> // `fsync`, `close`, `link`, `unlink`
#endif

namespace unum::ucall::tools {

/** Whether landing may replace a file already at the target, or must leave one there untouched. */
enum class landing_t { replace_k, create_k };

/** Who may read the landed file: everyone the umask lets, or its owner alone, as a private key
 *  needs. */
enum class readers_t { shared_k, owner_only_k };

/**
 *  @brief A file written into <tt>target.tmp</tt>, created exclusively without following a link, then
 *      flushed to the device and moved over the target, so a failure or a stop leaves a file
 *      already at the target as it was.
 *
 *  A stale temporary refuses the open rather than being overwritten, so two writers of one target
 *  never share it. On Windows the temporary is created exclusively, but a reparse point at its
 *  name is followed.
 */
class landed_file_t {
    static constexpr std::size_t path_bytes_k = 4096;
    char target_[path_bytes_k] {};
    char temporary_[path_bytes_k] {};
    std::FILE* file_ = nullptr;

    /** Makes the landed file's directory entry durable, where the platform syncs a directory. */
    bool sync_directory() const noexcept {
#if UCALL_OS_WINDOWS_
        return true;
#else
        char directory[path_bytes_k] {'.', '\0'};
        if (char const* slash = std::strrchr(target_, '/')) {
            std::size_t const length = slash == target_ ? 1 : static_cast<std::size_t>(slash - target_);
            std::memcpy(directory, target_, length);
            directory[length] = '\0';
        }
        int const descriptor = ::open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (descriptor < 0) return false;
        bool const synced = ::fsync(descriptor) == 0;
        return ::close(descriptor) == 0 && synced;
#endif
    }

    /** Moves the flushed temporary to the target, replacing a file there only on replace. */
    bool move(landing_t landing) const noexcept {
#if UCALL_OS_WINDOWS_
        DWORD const replace = landing == landing_t::replace_k ? MOVEFILE_REPLACE_EXISTING : 0;
        return ::MoveFileExA(temporary_, target_, replace | MOVEFILE_WRITE_THROUGH) != 0;
#else
        // A hard link refuses an existing name atomically, where a rename would replace it.
        if (landing == landing_t::replace_k) return std::rename(temporary_, target_) == 0;
        if (::link(temporary_, target_) != 0) return false;
        [[maybe_unused]] int const unlinked = ::unlink(temporary_);
        return true;
#endif
    }

  public:
    landed_file_t() noexcept = default;
    landed_file_t(landed_file_t const&) = delete;
    landed_file_t& operator=(landed_file_t const&) = delete;

    /** Removes a temporary that never landed. */
    ~landed_file_t() noexcept {
        if (!file_) return;
        [[maybe_unused]] int const closed = std::fclose(file_);
        [[maybe_unused]] int const removed = std::remove(temporary_);
    }

    /** Creates the temporary beside @p target for @p readers; answers false when the path is too
     *  long, or the temporary exists or won't open. Windows ignores @p readers, as its ACLs come
     *  from the directory. */
    bool open(char const* target, [[maybe_unused]] readers_t readers) noexcept {
        std::size_t const length = std::strlen(target);
        if (file_ || length + sizeof(".tmp") > path_bytes_k) return false;
        std::memcpy(target_, target, length + 1);
        std::memcpy(temporary_, target, length);
        std::memcpy(temporary_ + length, ".tmp", sizeof(".tmp"));
#if UCALL_OS_WINDOWS_
        int const descriptor = ::_open(temporary_, _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY, _S_IREAD | _S_IWRITE);
        if (descriptor < 0) return false;
        file_ = ::_fdopen(descriptor, "wb");
        if (!file_) ::_close(descriptor);
#else
        int const descriptor = ::open(temporary_, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                                      readers == readers_t::owner_only_k ? 0600 : 0666);
        if (descriptor < 0) return false;
        file_ = ::fdopen(descriptor, "wb");
        if (!file_) ::close(descriptor);
#endif
        if (file_) return true;
        [[maybe_unused]] int const removed = std::remove(temporary_);
        return false;
    }

    /** The stream writing the temporary. */
    [[nodiscard]] std::FILE* stream() const noexcept { return file_; }

    /** Flushes the temporary to the device and moves it over the target, removing it instead when
     *  any step fails; answers whether the target now holds the whole file. */
    bool land(landing_t landing) noexcept {
        if (!file_) return false;
        bool flushed = std::fflush(file_) == 0 && !std::ferror(file_);
#if UCALL_OS_WINDOWS_
        flushed = flushed && ::_commit(::_fileno(file_)) == 0;
#else
        flushed = flushed && ::fsync(::fileno(file_)) == 0;
#endif
        flushed = std::fclose(file_) == 0 && flushed;
        file_ = nullptr;
        if (!flushed || !move(landing)) {
            [[maybe_unused]] int const removed = std::remove(temporary_);
            return false;
        }
        return sync_directory();
    }
};

} // namespace unum::ucall::tools
