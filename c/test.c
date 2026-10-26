/**
 *  @file c/test.c
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief A C caller of the linked library's name, status, outcome, Noise key, and version
 *      functions.
 */
#undef NDEBUG
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ucall/ucall.h"

int main(void) {
    uint8_t const text[] = {'x', 'd', 'e', 'f', 'e', 'r', 'r', 'e', 'd', 'x'};
    ucall_bytes_view_t name = {text + 1, sizeof(text) - 2};
    assert(ucall_status_from_name(name) == ucall_status_deferred_k);
    assert(strcmp(ucall_status_name(ucall_status_deferred_k), "deferred") == 0);
    assert(strcmp(ucall_status_name((ucall_status_t)-1), "unrecognized") == 0);
    name.length = sizeof(text) - 1;
    assert(ucall_status_from_name(name) == ucall_status_invalid_argument_k);
    name.data = NULL;
    name.length = 0;
    assert(ucall_status_from_name(name) == ucall_status_invalid_argument_k);

    ucall_bytes_view_t backend = {(ucall_byte_t const*)"linux-epollaio", 14};
    assert(ucall_io_backend_from_name(backend) == ucall_io_backend_linux_epollaio_k);
    backend.length = 5;
    assert(ucall_io_backend_from_name(backend) == ucall_io_backend_automatic_k);
    ucall_bytes_view_t cpu_class = {(ucall_byte_t const*)"apple-m2", 8};
    assert(ucall_cpu_class_from_name(cpu_class) == ucall_cpu_class_apple_m2_k);
    cpu_class.data = NULL;
    cpu_class.length = 0;
    assert(ucall_cpu_class_from_name(cpu_class) == ucall_cpu_class_unknown_k);

    ucall_outcome_t outcome = {ucall_status_success_k, NULL};
    assert(ucall_outcome_status(&outcome) == ucall_status_success_k);
    assert(ucall_outcome_wait(&outcome) == ucall_status_success_k);

    ucall_noise_key_t private_key, public_key, derived_key, other_private_key, other_public_key;
    ucall_noise_key_generate_t generate = {&outcome, &private_key, &public_key};
    ucall_noise_key_generate(&generate);
    assert(outcome.status == ucall_status_success_k && outcome.message == NULL);
    ucall_noise_key_derive_t derive = {&outcome, (ucall_noise_key_t const*)&private_key, &derived_key};
    ucall_noise_key_derive(&derive);
    assert(outcome.status == ucall_status_success_k && memcmp(derived_key, public_key, sizeof(public_key)) == 0);
    generate.private_key = &other_private_key;
    generate.public_key = &other_public_key;
    ucall_noise_key_generate(&generate);
    assert(memcmp(other_private_key, private_key, sizeof(private_key)) != 0);
    derive.public_key = NULL;
    ucall_noise_key_derive(&derive);
    assert(outcome.status == ucall_status_invalid_argument_k);

    int major, minor, patch;
    ucall_version(&major, &minor, &patch);
    assert(major == UCALL_VERSION_MAJOR && minor == UCALL_VERSION_MINOR && patch == UCALL_VERSION_PATCH);
    char version[64];
    int length = snprintf(version, sizeof(version), "%d.%d.%d", major, minor, patch);
    assert(length > 0 && (size_t)length < sizeof(version));
    assert(strncmp(ucall_version_name(), version, (size_t)length) == 0);
    return 0;
}
