# UCall C SDK

C is the "Lingua franca" of modern computing, and we use it as our primary interface.
We wanted to make it as lightweight as possible and to allow optional arguments without dynamic allocations and named lookups.
So unlike the Python layer, we expect the user to manually extract the arguments from the call context with `ucall_param_named_i64()`, and its siblings.
The minimal sum example could look like this.

```c
#include <ucall/ucall.h>

static void sum(ucall_message_t call, ucall_endpoint_tag_t) {
    int64_t a{}, b{};
    char c_str[256]{};
    bool got_a = ucall_param_named_i64(call, "a", 0, &a);
    bool got_b = ucall_param_named_i64(call, "b", 0, &b);
    if (!got_a || !got_b)
        return ucall_reply_error_invalid_params(call);

    std::to_chars_result print = std::to_chars(&c_str[0], &c_str[0] + sizeof(c_str), a + b, 10);
    ucall_reply_content(call, &c_str[0], print.ptr - &c_str[0]);
}

int main(int argc, char** argv) {

    ucall_server_t server{};
    ucall_config_t config{};

    ucall_init(&config, &server);
    ucall_add_endpoint(server, "sum", &sum, post_k, NULL);
    ucall_take_calls(server, 0);
    ucall_free(server);
    return 0;
}
```

Longer than Python version, but tiny by C standards, and super fast.
