Expect-CT Lite Demo Code for OpenSSL
====================================

This is demo code for how to implement [“Expect-CT Lite", as proposed in this
article](https://www.devever.net/~hl/expect-ct-lite), using OpenSSL.

The idea is that this can make it easy for client applications to do
Certificate Transparency enforcement in a way which is better than not doing
any Certificate Transparency enforcement at all. (Of course, doing full
Certificate Transparency SCT signature validation is even better, but may
substantially increases application complexity and maintenance burden, [as
noted in the article](https://www.devever.net/~hl/expect-ct-lite).)

To use, run `make` to build, then run (for example) `./client
www.example.com:443`.

Released under the MIT License.

[If you have any comments or questions on this code, you can contact me
here.](https://www.devever.net/~hl/contact)
