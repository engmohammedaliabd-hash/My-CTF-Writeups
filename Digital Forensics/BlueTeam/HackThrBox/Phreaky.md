# HTB -  Phreaky - Forensics Write-up
**Author:** Mohammed Ali  
**Team:** CyberScope  
**Platform:** HackTheBox 
**Category:** Network Forensics  
**Difficulty:** Medium 

<img width="527" height="771" alt="image" src="https://github.com/user-attachments/assets/2e122f87-cd7a-4fa8-9cc8-e2ce97f0de66" />


## Challenge Description

The challenge provides a network packet capture (`phreaky.pcap`) containing SMTP traffic. The objective is to identify the leaked files, reconstruct the transferred document, and uncover the information hidden within it.

---

# Initial Analysis

The first step was identifying the protocols present in the capture.

```bash
tshark -r phreaky.pcap -Y smtp
```
```
 tshark -r phreaky.pcap -Y smtp
 2783 222.561630 192.168.68.111 → 192.168.68.108 SMTP 109 S: 220 The Phreaks Mail Server - We run this
 2785 222.561805 192.168.68.108 → 192.168.68.111 SMTP 88 C: HELO phreak-ubuntu01
 2787 222.561869 192.168.68.111 → 192.168.68.108 SMTP 89 S: 250 mailserver-phreak
 2788 222.562004 192.168.68.108 → 192.168.68.111 SMTP 100 C: MAIL FROM:<caleb@thephreaks.com>
 2789 222.564620 192.168.68.111 → 192.168.68.108 SMTP 80 S: 250 2.1.0 Ok
 2790 222.564734 192.168.68.108 → 192.168.68.111 SMTP 102 C: RCPT TO:<resources@thetalents.com>
 2791 222.566912 192.168.68.111 → 192.168.68.108 SMTP 80 S: 250 2.1.5 Ok
 2792 222.567009 192.168.68.108 → 192.168.68.111 SMTP 72 C: DATA
 2793 222.567044 192.168.68.111 → 192.168.68.108 SMTP 103 S: 354 End data with <CR><LF>.<CR><LF>
 2794 222.567128 192.168.68.108 → 192.168.68.111 SMTP 105 C: DATA fragment, 39 bytes
 2795 222.567154 192.168.68.108 → 192.168.68.111 SMTP 1514 C: DATA fragment, 1448 bytes
 2797 222.567231 192.168.68.108 → 192.168.68.111 SMTP/IMF 141 from: caleb@thephreaks.com(Caleb), subject: Secure File Transfer,  (text/plain) (application/zip) | .
 2798 222.567804 192.168.68.111 → 192.168.68.108 SMTP 101 S: 250 2.0.0 Ok: queued as 9CB872113
 2799 222.567878 192.168.68.108 → 192.168.68.111 SMTP 72 C: QUIT
 2800 222.568241 192.168.68.111 → 192.168.68.108 SMTP 81 S: 221 2.0.0 Bye
 2817 223.304220 204.141.43.44 → 192.168.68.111 SMTP 134 S: 220 mx.zohomail.com SMTP Server ready March 6, 2024 6:59:13 AM PST
 2819 223.304314 192.168.68.111 → 204.141.43.44 SMTP 90 C: EHLO mailserver-phreak
 2821 224.100609 204.141.43.44 → 192.168.68.111 SMTP 180 S: 250-mx.zohomail.com Hello mailserver-phreak (cpc111699-linc13-2-0-cust632.12-1.cable.virginm.net (86.5.206.121))
 2822 224.100609 204.141.43.44 → 192.168.68.111 SMTP 80 S: 250-STARTTLS
 2824 224.100771 204.141.43.44 → 192.168.68.111 SMTP 80 S: 250-8BITMIME
 2825 224.100895 204.141.43.44 → 192.168.68.111 SMTP 85 S: 250 SIZE 53477376
 2827 224.100944 192.168.68.111 → 204.141.43.44 SMTP 76 C: STARTTLS
 2829 224.274275 204.141.43.44 → 192.168.68.111 SMTP 91 S: 220 Ready to start TLS.
 2866 342.727287 192.168.68.111 → 192.168.68.108 SMTP 109 S: 220 The Phreaks Mail Server - We run this
 2868 342.727492 192.168.68.108 → 192.168.68.111 SMTP 88 C: HELO phreak-ubuntu01
 2870 342.727559 192.168.68.111 → 192.168.68.108 SMTP 89 S: 250 mailserver-phreak
 2871 342.727638 192.168.68.108 → 192.168.68.111 SMTP 100 C: MAIL FROM:<caleb@thephreaks.com>
 2872 342.730396 192.168.68.111 → 192.168.68.108 SMTP 80 S: 250 2.1.0 Ok
 2873 342.730500 192.168.68.108 → 192.168.68.111 SMTP 102 C: RCPT TO:<resources@thetalents.com>
 2874 342.732660 192.168.68.111 → 192.168.68.108 SMTP 80 S: 250 2.1.5 Ok
 2875 342.732741 192.168.68.108 → 192.168.68.111 SMTP 72 C: DATA
 2876 342.732775 192.168.68.111 → 192.168.68.108 SMTP 103 S: 354 End data with <CR><LF>.<CR><LF>
 2877 342.732876 192.168.68.108 → 192.168.68.111 SMTP 105 C: DATA fragment, 39 bytes
 2878 342.732902 192.168.68.108 → 192.168.68.111 SMTP 1514 C: DATA fragment, 1448 bytes
 2880 342.732995 192.168.68.108 → 192.168.68.111 SMTP/IMF 161 from: caleb@thephreaks.com(Caleb), subject: Secure File Transfer,  (text/plain) (application/zip) | .
 2881 342.733836 192.168.68.111 → 192.168.68.108 SMTP 101 S: 250 2.0.0 Ok: queued as C53572113
 2882 342.733906 192.168.68.108 → 192.168.68.111 SMTP 72 C: QUIT
 2883 342.733938 192.168.68.111 → 192.168.68.108 SMTP 81 S: 221 2.0.0 Bye
 2894 343.165782 204.141.43.44 → 192.168.68.111 SMTP 134 S: 220 mx.zohomail.com SMTP Server ready March 6, 2024 7:01:13 AM PST
 2896 343.165965 192.168.68.111 → 204.141.43.44 SMTP 90 C: EHLO mailserver-phreak
 2898 343.773769 204.141.43.44 → 192.168.68.111 SMTP 180 S: 250-mx.zohomail.com Hello mailserver-phreak (cpc111699-linc13-2-0-cust632.12-1.cable.virginm.net (86.5.206.121))
 2899 343.774247 204.141.43.44 → 192.168.68.111 SMTP 80 S: 250-STARTTLS
 2901 343.774736 204.141.43.44 → 192.168.68.111 SMTP 80 S: 250-8BITMIME
 2902 343.775210 204.141.43.44 → 192.168.68.111 SMTP 85 S: 250 SIZE 53477376
 2904 343.775267 192.168.68.111 → 204.141.43.44 SMTP 76 C: STARTTLS
 2906 343.946828 204.141.43.44 → 192.168.68.111 SMTP 91 S: 220 Ready to start TLS.
 2940 462.881225 192.168.68.111 → 192.168.68.108 SMTP 109 S: 220 The Phreaks Mail Server - We run this
 2942 462.881511 192.168.68.108 → 192.168.68.111 SMTP 88 C: HELO phreak-ubuntu01
 2944 462.881549 192.168.68.111 → 192.168.68.108 SMTP 89 S: 250 mailserver-phreak
 2945 462.881758 192.168.68.108 → 192.168.68.111 SMTP 100 C: MAIL FROM:<caleb@thephreaks.com>
 2946 462.884128 192.168.68.111 → 192.168.68.108 SMTP 80 S: 250 2.1.0 Ok
 2947 462.884281 192.168.68.108 → 192.168.68.111 SMTP 102 C: RCPT TO:<resources@thetalents.com>
 2948 462.886464 192.168.68.111 → 192.168.68.108 SMTP 80 S: 250 2.1.5 Ok
 2949 462.886631 192.168.68.108 → 192.168.68.111 SMTP 72 C: DATA
 2950 462.886672 192.168.68.111 → 192.168.68.108 SMTP 103 S: 354 End data with <CR><LF>.<CR><LF>
 2951 462.886847 192.168.68.108 → 192.168.68.111 SMTP 105 C: DATA fragment, 39 bytes
 2952 462.886847 192.168.68.108 → 192.168.68.111 SMTP 1514 C: DATA fragment, 1448 bytes
 2954 462.886969 192.168.68.108 → 192.168.68.111 SMTP/IMF 161 from: caleb@thephreaks.com(Caleb), subject: Secure File Transfer,  (text/plain) (application/zip) | .
 2955 462.887953 192.168.68.111 → 192.168.68.108 SMTP 101 S: 250 2.0.0 Ok: queued as EABB42113
 2956 462.888090 192.168.68.108 → 192.168.68.111 SMTP 72 C: QUIT
 2957 462.888170 192.168.68.111 → 192.168.68.108 SMTP 81 S: 221 2.0.0 Bye
 2968 463.269277 204.141.43.44 → 192.168.68.111 SMTP 134 S: 220 mx.zohomail.com SMTP Server ready March 6, 2024 7:03:13 AM PST
 2970 463.269398 192.168.68.111 → 204.141.43.44 SMTP 90 C: EHLO mailserver-phreak
 2972 463.617177 204.141.43.44 → 192.168.68.111 SMTP 180 S: 250-mx.zohomail.com Hello mailserver-phreak (cpc111699-linc13-2-0-cust632.12-1.cable.virginm.net (86.5.206.121))
 2973 463.617664 204.141.43.44 → 192.168.68.111 SMTP 80 S: 250-STARTTLS
 2975 463.618175 204.141.43.44 → 192.168.68.111 SMTP 99 S: 250-8BITMIME | SIZE 53477376
 2976 463.618196 192.168.68.111 → 204.141.43.44 SMTP 76 C: STARTTLS
 2978 463.789639 204.141.43.44 → 192.168.68.111 SMTP 91 S: 220 Ready to start TLS.
 3013 583.029170 192.168.68.111 → 192.168.68.108 SMTP 109 S: 220 The Phreaks Mail Server - We run this
 3015 583.029396 192.168.68.108 → 192.168.68.111 SMTP 88 C: HELO phreak-ubuntu01
 3017 583.029451 192.168.68.111 → 192.168.68.108 SMTP 89 S: 250 mailserver-phreak
 3018 583.029613 192.168.68.108 → 192.168.68.111 SMTP 100 C: MAIL FROM:<caleb@thephreaks.com>
 3019 583.032087 192.168.68.111 → 192.168.68.108 SMTP 80 S: 250 2.1.0 Ok
 3020 583.032205 192.168.68.108 → 192.168.68.111 SMTP 102 C: RCPT TO:<resources@thetalents.com>
 3021 583.034471 192.168.68.111 → 192.168.68.108 SMTP 80 S: 250 2.1.5 Ok
 3022 583.034608 192.168.68.108 → 192.168.68.111 SMTP 72 C: DATA
 3023 583.034637 192.168.68.111 → 192.168.68.108 SMTP 103 S: 354 End data with <CR><LF>.<CR><LF>
 3024 583.034745 192.168.68.108 → 192.168.68.111 SMTP 105 C: DATA fragment, 39 bytes
 3025 583.034773 192.168.68.108 → 192.168.68.111 SMTP 1514 C: DATA fragment, 1448 bytes
 3027 583.034854 192.168.68.108 → 192.168.68.111 SMTP/IMF 161 from: caleb@thephreaks.com(Caleb), subject: Secure File Transfer,  (text/plain) (application/zip) | .
 3028 583.035667 192.168.68.111 → 192.168.68.108 SMTP 101 S: 250 2.0.0 Ok: queued as 1AB9F2113
 3029 583.035748 192.168.68.108 → 192.168.68.111 SMTP 72 C: QUIT
 3030 583.035831 192.168.68.111 → 192.168.68.108 SMTP 81 S: 221 2.0.0 Bye
 3041 583.422656 204.141.43.44 → 192.168.68.111 SMTP 134 S: 220 mx.zohomail.com SMTP Server ready March 6, 2024 7:05:13 AM PST
 3043 583.422854 192.168.68.111 → 204.141.43.44 SMTP 90 C: EHLO mailserver-phreak
 3045 583.847111 204.141.43.44 → 192.168.68.111 SMTP 180 S: 250-mx.zohomail.com Hello mailserver-phreak (cpc111699-linc13-2-0-cust632.12-1.cable.virginm.net (86.5.206.121))
 3046 583.847586 204.141.43.44 → 192.168.68.111 SMTP 80 S: 250-STARTTLS
 3048 583.847912 204.141.43.44 → 192.168.68.111 SMTP 80 S: 250-8BITMIME
 3049 583.848456 204.141.43.44 → 192.168.68.111 SMTP 85 S: 250 SIZE 53477376
 3051 583.848583 192.168.68.111 → 204.141.43.44 SMTP 76 C: STARTTLS
 3053 584.021306 204.141.43.44 → 192.168.68.111 SMTP 91 S: 220 Ready to start TLS.
 3090 703.155293 192.168.68.111 → 192.168.68.108 SMTP 109 S: 220 The Phreaks Mail Server - We run this
 3092 703.155452 192.168.68.108 → 192.168.68.111 SMTP 88 C: HELO phreak-ubuntu01
 3094 703.155500 192.168.68.111 → 192.168.68.108 SMTP 89 S: 250 mailserver-phreak
 3095 703.155563 192.168.68.108 → 192.168.68.111 SMTP 100 C: MAIL FROM:<caleb@thephreaks.com>
 3096 703.158130 192.168.68.111 → 192.168.68.108 SMTP 80 S: 250 2.1.0 Ok
 3097 703.158213 192.168.68.108 → 192.168.68.111 SMTP 102 C: RCPT TO:<resources@thetalents.com>
 3098 703.160279 192.168.68.111 → 192.168.68.108 SMTP 80 S: 250 2.1.5 Ok
 3099 703.160368 192.168.68.108 → 192.168.68.111 SMTP 72 C: DATA
 3100 703.160408 192.168.68.111 → 192.168.68.108 SMTP 103 S: 354 End data with <CR><LF>.<CR><LF>
 3101 703.160505 192.168.68.108 → 192.168.68.111 SMTP 105 C: DATA fragment, 39 bytes
 3102 703.160527 192.168.68.108 → 192.168.68.111 SMTP 1514 C: DATA fragment, 1448 bytes
 3104 703.160634 192.168.68.108 → 192.168.68.111 SMTP/IMF 161 from: caleb@thephreaks.com(Caleb), subject: Secure File Transfer,  (text/plain) (application/zip) | .
 3105 703.161033 192.168.68.111 → 192.168.68.108 SMTP 101 S: 250 2.0.0 Ok: queued as 397892113
 3106 703.161098 192.168.68.108 → 192.168.68.111 SMTP 72 C: QUIT
 3107 703.161185 192.168.68.111 → 192.168.68.108 SMTP 81 S: 221 2.0.0 Bye
 3118 703.552915 204.141.43.44 → 192.168.68.111 SMTP 134 S: 220 mx.zohomail.com SMTP Server ready March 6, 2024 7:07:13 AM PST
 3120 703.553049 192.168.68.111 → 204.141.43.44 SMTP 90 C: EHLO mailserver-phreak
 3122 703.732091 204.141.43.44 → 192.168.68.111 SMTP 180 S: 250-mx.zohomail.com Hello mailserver-phreak (cpc111699-linc13-2-0-cust632.12-1.cable.virginm.net (86.5.206.121))
 3123 703.732574 204.141.43.44 → 192.168.68.111 SMTP 80 S: 250-STARTTLS
 3125 703.732979 204.141.43.44 → 192.168.68.111 SMTP 80 S: 250-8BITMIME
 3126 703.733446 204.141.43.44 → 192.168.68.111 SMTP 85 S: 250 SIZE 53477376
 3128 703.733512 192.168.68.111 → 204.141.43.44 SMTP 76 C: STARTTLS
 3129 703.910854 204.141.43.44 → 192.168.68.111 SMTP 91 S: 220 Ready to start TLS.
 3165 823.316849 192.168.68.111 → 192.168.68.108 SMTP 109 S: 220 The Phreaks Mail Server - We run this
 3167 823.317057 192.168.68.108 → 192.168.68.111 SMTP 88 C: HELO phreak-ubuntu01
 3169 823.317097 192.168.68.111 → 192.168.68.108 SMTP 89 S: 250 mailserver-phreak
 3170 823.317243 192.168.68.108 → 192.168.68.111 SMTP 100 C: MAIL FROM:<caleb@thephreaks.com>
 3171 823.320946 192.168.68.111 → 192.168.68.108 SMTP 80 S: 250 2.1.0 Ok
 3172 823.321133 192.168.68.108 → 192.168.68.111 SMTP 102 C: RCPT TO:<resources@thetalents.com>
 3173 823.324915 192.168.68.111 → 192.168.68.108 SMTP 80 S: 250 2.1.5 Ok
 3174 823.325049 192.168.68.108 → 192.168.68.111 SMTP 72 C: DATA
 3175 823.325080 192.168.68.111 → 192.168.68.108 SMTP 103 S: 354 End data with <CR><LF>.<CR><LF>
 3176 823.325202 192.168.68.108 → 192.168.68.111 SMTP 105 C: DATA fragment, 39 bytes
 3177 823.325237 192.168.68.108 → 192.168.68.111 SMTP 1514 C: DATA fragment, 1448 bytes
 3179 823.325350 192.168.68.108 → 192.168.68.111 SMTP/IMF 129 from: caleb@thephreaks.com(Caleb), subject: Secure File Transfer,  (text/plain) (application/zip) | .
 3180 823.326375 192.168.68.111 → 192.168.68.108 SMTP 101 S: 250 2.0.0 Ok: queued as 61A082113
 3181 823.326462 192.168.68.108 → 192.168.68.111 SMTP 72 C: QUIT
 3182 823.326546 192.168.68.111 → 192.168.68.108 SMTP 81 S: 221 2.0.0 Bye
 3197 824.214115 204.141.43.44 → 192.168.68.111 SMTP 134 S: 220 mx.zohomail.com SMTP Server ready March 6, 2024 7:09:14 AM PST
 3199 824.214235 192.168.68.111 → 204.141.43.44 SMTP 90 C: EHLO mailserver-phreak
 3201 824.387032 204.141.43.44 → 192.168.68.111 SMTP 180 S: 250-mx.zohomail.com Hello mailserver-phreak (cpc111699-linc13-2-0-cust632.12-1.cable.virginm.net (86.5.206.121))
 3202 824.387606 204.141.43.44 → 192.168.68.111 SMTP 80 S: 250-STARTTLS
 3204 824.388169 204.141.43.44 → 192.168.68.111 SMTP 80 S: 250-8BITMIME
 3205 824.388702 204.141.43.44 → 192.168.68.111 SMTP 85 S: 250 SIZE 53477376
 3207 824.388749 192.168.68.111 → 204.141.43.44 SMTP 76 C: STARTTLS
 3208 824.558612 204.141.43.44 → 192.168.68.111 SMTP 91 S: 220 Ready to start TLS.
 3243 943.467750 192.168.68.111 → 192.168.68.108 SMTP 109 S: 220 The Phreaks Mail Server - We run this
 3245 943.467951 192.168.68.108 → 192.168.68.111 SMTP 88 C: HELO phreak-ubuntu01
 3247 943.468011 192.168.68.111 → 192.168.68.108 SMTP 89 S: 250 mailserver-phreak
 3248 943.468146 192.168.68.108 → 192.168.68.111 SMTP 100 C: MAIL FROM:<caleb@thephreaks.com>
 3249 943.470588 192.168.68.111 → 192.168.68.108 SMTP 80 S: 250 2.1.0 Ok
 3250 943.470794 192.168.68.108 → 192.168.68.111 SMTP 102 C: RCPT TO:<resources@thetalents.com>
 3251 943.472871 192.168.68.111 → 192.168.68.108 SMTP 80 S: 250 2.1.5 Ok
 3252 943.473108 192.168.68.108 → 192.168.68.111 SMTP 72 C: DATA
 3253 943.473144 192.168.68.111 → 192.168.68.108 SMTP 103 S: 354 End data with <CR><LF>.<CR><LF>
 3254 943.473326 192.168.68.108 → 192.168.68.111 SMTP 105 C: DATA fragment, 39 bytes
 3255 943.473326 192.168.68.108 → 192.168.68.111 SMTP 1514 C: DATA fragment, 1448 bytes
 3257 943.473508 192.168.68.108 → 192.168.68.111 SMTP/IMF 161 from: caleb@thephreaks.com(Caleb), subject: Secure File Transfer,  (text/plain) (application/zip) | .
 3258 943.474237 192.168.68.111 → 192.168.68.108 SMTP 101 S: 250 2.0.0 Ok: queued as 85C8E2113
 3259 943.474335 192.168.68.108 → 192.168.68.111 SMTP 72 C: QUIT
 3260 943.474366 192.168.68.111 → 192.168.68.108 SMTP 81 S: 221 2.0.0 Bye
 3271 943.885427 204.141.43.44 → 192.168.68.111 SMTP 134 S: 220 mx.zohomail.com SMTP Server ready March 6, 2024 7:11:13 AM PST
 3273 943.885587 192.168.68.111 → 204.141.43.44 SMTP 90 C: EHLO mailserver-phreak
 3275 944.071367 204.141.43.44 → 192.168.68.111 SMTP 180 S: 250-mx.zohomail.com Hello mailserver-phreak (cpc111699-linc13-2-0-cust632.12-1.cable.virginm.net (86.5.206.121))
 3276 944.071909 204.141.43.44 → 192.168.68.111 SMTP 80 S: 250-STARTTLS
 3278 944.072259 204.141.43.44 → 192.168.68.111 SMTP 80 S: 250-8BITMIME
 3279 944.072729 204.141.43.44 → 192.168.68.111 SMTP 85 S: 250 SIZE 53477376
 3281 944.072840 192.168.68.111 → 204.141.43.44 SMTP 76 C: STARTTLS
 3282 944.257774 204.141.43.44 → 192.168.68.111 SMTP 91 S: 220 Ready to start TLS.
 3318 1063.619887 192.168.68.111 → 192.168.68.108 SMTP 109 S: 220 The Phreaks Mail Server - We run this
 3320 1063.620153 192.168.68.108 → 192.168.68.111 SMTP 88 C: HELO phreak-ubuntu01
 3322 1063.620212 192.168.68.111 → 192.168.68.108 SMTP 89 S: 250 mailserver-phreak
 3323 1063.620292 192.168.68.108 → 192.168.68.111 SMTP 100 C: MAIL FROM:<caleb@thephreaks.com>
 3324 1063.624118 192.168.68.111 → 192.168.68.108 SMTP 80 S: 250 2.1.0 Ok
 3325 1063.624289 192.168.68.108 → 192.168.68.111 SMTP 102 C: RCPT TO:<resources@thetalents.com>
 3326 1063.627550 192.168.68.111 → 192.168.68.108 SMTP 80 S: 250 2.1.5 Ok
 3327 1063.627692 192.168.68.108 → 192.168.68.111 SMTP 72 C: DATA
 3328 1063.627744 192.168.68.111 → 192.168.68.108 SMTP 103 S: 354 End data with <CR><LF>.<CR><LF>
 3329 1063.627828 192.168.68.108 → 192.168.68.111 SMTP 105 C: DATA fragment, 39 bytes
 3330 1063.627870 192.168.68.108 → 192.168.68.111 SMTP 1514 C: DATA fragment, 1448 bytes
 3332 1063.627952 192.168.68.108 → 192.168.68.111 SMTP/IMF 161 from: caleb@thephreaks.com(Caleb), subject: Secure File Transfer,  (text/plain) (application/zip) | .
 3333 1063.628861 192.168.68.111 → 192.168.68.108 SMTP 101 S: 250 2.0.0 Ok: queued as AB89E2113
 3334 1063.628972 192.168.68.108 → 192.168.68.111 SMTP 72 C: QUIT
 3335 1063.629031 192.168.68.111 → 192.168.68.108 SMTP 81 S: 221 2.0.0 Bye
 3347 1064.030215 204.141.43.44 → 192.168.68.111 SMTP 134 S: 220 mx.zohomail.com SMTP Server ready March 6, 2024 7:13:14 AM PST
 3349 1064.030343 192.168.68.111 → 204.141.43.44 SMTP 90 C: EHLO mailserver-phreak
 3351 1064.212119 204.141.43.44 → 192.168.68.111 SMTP 180 S: 250-mx.zohomail.com Hello mailserver-phreak (cpc111699-linc13-2-0-cust632.12-1.cable.virginm.net (86.5.206.121))
 3352 1064.212267 204.141.43.44 → 192.168.68.111 SMTP 80 S: 250-STARTTLS
 3354 1064.212746 204.141.43.44 → 192.168.68.111 SMTP 80 S: 250-8BITMIME
 3355 1064.213193 204.141.43.44 → 192.168.68.111 SMTP 85 S: 250 SIZE 53477376
 3357 1064.213255 192.168.68.111 → 204.141.43.44 SMTP 76 C: STARTTLS
 3358 1064.392137 204.141.43.44 → 192.168.68.111 SMTP 91 S: 220 Ready to start TLS.
 3393 1183.765084 192.168.68.111 → 192.168.68.108 SMTP 109 S: 220 The Phreaks Mail Server - We run this
 3395 1183.765394 192.168.68.108 → 192.168.68.111 SMTP 88 C: HELO phreak-ubuntu01
 3397 1183.765511 192.168.68.111 → 192.168.68.108 SMTP 89 S: 250 mailserver-phreak
 3398 1183.765795 192.168.68.108 → 192.168.68.111 SMTP 100 C: MAIL FROM:<caleb@thephreaks.com>
 3399 1183.769663 192.168.68.111 → 192.168.68.108 SMTP 80 S: 250 2.1.0 Ok
 3400 1183.769977 192.168.68.108 → 192.168.68.111 SMTP 102 C: RCPT TO:<resources@thetalents.com>
 3401 1183.773205 192.168.68.111 → 192.168.68.108 SMTP 80 S: 250 2.1.5 Ok
 3402 1183.773436 192.168.68.108 → 192.168.68.111 SMTP 72 C: DATA
 3403 1183.773474 192.168.68.111 → 192.168.68.108 SMTP 103 S: 354 End data with <CR><LF>.<CR><LF>
 3404 1183.773697 192.168.68.108 → 192.168.68.111 SMTP 105 C: DATA fragment, 39 bytes
 3405 1183.773697 192.168.68.108 → 192.168.68.111 SMTP 1514 C: DATA fragment, 1448 bytes
 3407 1183.773888 192.168.68.108 → 192.168.68.111 SMTP/IMF 161 from: caleb@thephreaks.com(Caleb), subject: Secure File Transfer,  (text/plain) (application/zip) | .
 3408 1183.774582 192.168.68.111 → 192.168.68.108 SMTP 101 S: 250 2.0.0 Ok: queued as CF1C02113
 3409 1183.774747 192.168.68.108 → 192.168.68.111 SMTP 72 C: QUIT
 3410 1183.774786 192.168.68.111 → 192.168.68.108 SMTP 81 S: 221 2.0.0 Bye
 3421 1184.169297 204.141.43.44 → 192.168.68.111 SMTP 134 S: 220 mx.zohomail.com SMTP Server ready March 6, 2024 7:15:14 AM PST
 3423 1184.169474 192.168.68.111 → 204.141.43.44 SMTP 90 C: EHLO mailserver-phreak
 3425 1184.348388 204.141.43.44 → 192.168.68.111 SMTP 180 S: 250-mx.zohomail.com Hello mailserver-phreak (cpc111699-linc13-2-0-cust632.12-1.cable.virginm.net (86.5.206.121))
 3426 1184.348866 204.141.43.44 → 192.168.68.111 SMTP 80 S: 250-STARTTLS
 3428 1184.349471 204.141.43.44 → 192.168.68.111 SMTP 80 S: 250-8BITMIME
 3429 1184.349916 204.141.43.44 → 192.168.68.111 SMTP 85 S: 250 SIZE 53477376
 3431 1184.349961 192.168.68.111 → 204.141.43.44 SMTP 76 C: STARTTLS
 3432 1184.528668 204.141.43.44 → 192.168.68.111 SMTP 91 S: 220 Ready to start TLS.
 3466 1303.901865 192.168.68.111 → 192.168.68.108 SMTP 109 S: 220 The Phreaks Mail Server - We run this
 3468 1303.902037 192.168.68.108 → 192.168.68.111 SMTP 88 C: HELO phreak-ubuntu01
 3470 1303.902075 192.168.68.111 → 192.168.68.108 SMTP 89 S: 250 mailserver-phreak
 3471 1303.902141 192.168.68.108 → 192.168.68.111 SMTP 100 C: MAIL FROM:<caleb@thephreaks.com>
 3472 1303.904577 192.168.68.111 → 192.168.68.108 SMTP 80 S: 250 2.1.0 Ok
 3473 1303.904706 192.168.68.108 → 192.168.68.111 SMTP 102 C: RCPT TO:<resources@thetalents.com>
 3474 1303.906758 192.168.68.111 → 192.168.68.108 SMTP 80 S: 250 2.1.5 Ok
 3475 1303.906830 192.168.68.108 → 192.168.68.111 SMTP 72 C: DATA
 3476 1303.906868 192.168.68.111 → 192.168.68.108 SMTP 103 S: 354 End data with <CR><LF>.<CR><LF>
 3477 1303.906955 192.168.68.108 → 192.168.68.111 SMTP 105 C: DATA fragment, 39 bytes
 3478 1303.906969 192.168.68.108 → 192.168.68.111 SMTP 1514 C: DATA fragment, 1448 bytes
 3480 1303.907033 192.168.68.108 → 192.168.68.111 SMTP/IMF 165 from: caleb@thephreaks.com(Caleb), subject: Secure File Transfer,  (text/plain) (application/zip) | .
 3481 1303.907536 192.168.68.111 → 192.168.68.108 SMTP 101 S: 250 2.0.0 Ok: queued as EFB712113
 3482 1303.907600 192.168.68.108 → 192.168.68.111 SMTP 72 C: QUIT
 3483 1303.907635 192.168.68.111 → 192.168.68.108 SMTP 81 S: 221 2.0.0 Bye
 3494 1304.300785 204.141.43.44 → 192.168.68.111 SMTP 134 S: 220 mx.zohomail.com SMTP Server ready March 6, 2024 7:17:14 AM PST
 3496 1304.300941 192.168.68.111 → 204.141.43.44 SMTP 90 C: EHLO mailserver-phreak
 3498 1304.482787 204.141.43.44 → 192.168.68.111 SMTP 180 S: 250-mx.zohomail.com Hello mailserver-phreak (cpc111699-linc13-2-0-cust632.12-1.cable.virginm.net (86.5.206.121))
 3499 1304.483285 204.141.43.44 → 192.168.68.111 SMTP 80 S: 250-STARTTLS
 3501 1304.483820 204.141.43.44 → 192.168.68.111 SMTP 99 S: 250-8BITMIME | SIZE 53477376
 3502 1304.483870 192.168.68.111 → 204.141.43.44 SMTP 76 C: STARTTLS
 3503 1304.666201 204.141.43.44 → 192.168.68.111 SMTP 91 S: 220 Ready to start TLS.
 3540 1424.056489 192.168.68.111 → 192.168.68.108 SMTP 109 S: 220 The Phreaks Mail Server - We run this
 3542 1424.056713 192.168.68.108 → 192.168.68.111 SMTP 88 C: HELO phreak-ubuntu01
 3544 1424.056752 192.168.68.111 → 192.168.68.108 SMTP 89 S: 250 mailserver-phreak
 3545 1424.056866 192.168.68.108 → 192.168.68.111 SMTP 100 C: MAIL FROM:<caleb@thephreaks.com>
 3546 1424.059234 192.168.68.111 → 192.168.68.108 SMTP 80 S: 250 2.1.0 Ok
 3547 1424.059391 192.168.68.108 → 192.168.68.111 SMTP 102 C: RCPT TO:<resources@thetalents.com>
 3548 1424.061541 192.168.68.111 → 192.168.68.108 SMTP 80 S: 250 2.1.5 Ok
 3549 1424.061689 192.168.68.108 → 192.168.68.111 SMTP 72 C: DATA
 3550 1424.061715 192.168.68.111 → 192.168.68.108 SMTP 103 S: 354 End data with <CR><LF>.<CR><LF>
 3551 1424.061885 192.168.68.108 → 192.168.68.111 SMTP 105 C: DATA fragment, 39 bytes
 3552 1424.061885 192.168.68.108 → 192.168.68.111 SMTP 1514 C: DATA fragment, 1448 bytes
 3554 1424.061992 192.168.68.108 → 192.168.68.111 SMTP/IMF 121 from: caleb@thephreaks.com(Caleb), subject: Secure File Transfer,  (text/plain) (application/zip) | .
 3555 1424.062769 192.168.68.111 → 192.168.68.108 SMTP 101 S: 250 2.0.0 Ok: queued as 215702113
 3556 1424.062888 192.168.68.108 → 192.168.68.111 SMTP 72 C: QUIT
 3557 1424.063118 192.168.68.111 → 192.168.68.108 SMTP 81 S: 221 2.0.0 Bye
 3572 1424.767174 204.141.43.44 → 192.168.68.111 SMTP 134 S: 220 mx.zohomail.com SMTP Server ready March 6, 2024 7:19:14 AM PST
 3574 1424.767286 192.168.68.111 → 204.141.43.44 SMTP 90 C: EHLO mailserver-phreak
 3576 1424.940042 204.141.43.44 → 192.168.68.111 SMTP 180 S: 250-mx.zohomail.com Hello mailserver-phreak (cpc111699-linc13-2-0-cust632.12-1.cable.virginm.net (86.5.206.121))
 3577 1424.940513 204.141.43.44 → 192.168.68.111 SMTP 80 S: 250-STARTTLS
 3579 1424.941022 204.141.43.44 → 192.168.68.111 SMTP 80 S: 250-8BITMIME
 3580 1424.941446 204.141.43.44 → 192.168.68.111 SMTP 85 S: 250 SIZE 53477376
 3582 1424.941476 192.168.68.111 → 204.141.43.44 SMTP 76 C: STARTTLS
 3583 1425.111910 204.141.43.44 → 192.168.68.111 SMTP 91 S: 220 Ready to start TLS.
 3618 1544.226862 192.168.68.111 → 192.168.68.108 SMTP 109 S: 220 The Phreaks Mail Server - We run this
 3620 1544.227032 192.168.68.108 → 192.168.68.111 SMTP 88 C: HELO phreak-ubuntu01
 3622 1544.227067 192.168.68.111 → 192.168.68.108 SMTP 89 S: 250 mailserver-phreak
 3623 1544.227129 192.168.68.108 → 192.168.68.111 SMTP 100 C: MAIL FROM:<caleb@thephreaks.com>
 3624 1544.229504 192.168.68.111 → 192.168.68.108 SMTP 80 S: 250 2.1.0 Ok
 3625 1544.229644 192.168.68.108 → 192.168.68.111 SMTP 102 C: RCPT TO:<resources@thetalents.com>
 3626 1544.231723 192.168.68.111 → 192.168.68.108 SMTP 80 S: 250 2.1.5 Ok
 3627 1544.231856 192.168.68.108 → 192.168.68.111 SMTP 72 C: DATA
 3628 1544.231881 192.168.68.111 → 192.168.68.108 SMTP 103 S: 354 End data with <CR><LF>.<CR><LF>
 3629 1544.231989 192.168.68.108 → 192.168.68.111 SMTP 105 C: DATA fragment, 39 bytes
 3631 1544.272789 192.168.68.108 → 192.168.68.111 SMTP/IMF 1453 from: caleb@thephreaks.com(Caleb), subject: Secure File Transfer,  (text/plain) (application/zip) | .
 3633 1544.273686 192.168.68.111 → 192.168.68.108 SMTP 101 S: 250 2.0.0 Ok: queued as 4AE3B2113
 3634 1544.273786 192.168.68.108 → 192.168.68.111 SMTP 72 C: QUIT
 3635 1544.274043 192.168.68.111 → 192.168.68.108 SMTP 81 S: 221 2.0.0 Bye
 3646 1544.675265 204.141.43.44 → 192.168.68.111 SMTP 134 S: 220 mx.zohomail.com SMTP Server ready March 6, 2024 7:21:14 AM PST
 3648 1544.675424 192.168.68.111 → 204.141.43.44 SMTP 90 C: EHLO mailserver-phreak
 3650 1544.857018 204.141.43.44 → 192.168.68.111 SMTP 180 S: 250-mx.zohomail.com Hello mailserver-phreak (cpc111699-linc13-2-0-cust632.12-1.cable.virginm.net (86.5.206.121))
 3651 1544.857494 204.141.43.44 → 192.168.68.111 SMTP 80 S: 250-STARTTLS
 3653 1544.857991 204.141.43.44 → 192.168.68.111 SMTP 99 S: 250-8BITMIME | SIZE 53477376
 3654 1544.858022 192.168.68.111 → 204.141.43.44 SMTP 76 C: STARTTLS
 3655 1545.040876 204.141.43.44 → 192.168.68.111 SMTP 91 S: 220 Ready to start TLS.
 3690 1664.409381 192.168.68.111 → 192.168.68.108 SMTP 109 S: 220 The Phreaks Mail Server - We run this
 3692 1664.409622 192.168.68.108 → 192.168.68.111 SMTP 88 C: HELO phreak-ubuntu01
 3694 1664.409678 192.168.68.111 → 192.168.68.108 SMTP 89 S: 250 mailserver-phreak
 3695 1664.409748 192.168.68.108 → 192.168.68.111 SMTP 100 C: MAIL FROM:<caleb@thephreaks.com>
 3696 1664.413402 192.168.68.111 → 192.168.68.108 SMTP 80 S: 250 2.1.0 Ok
 3697 1664.413623 192.168.68.108 → 192.168.68.111 SMTP 102 C: RCPT TO:<resources@thetalents.com>
 3698 1664.416723 192.168.68.111 → 192.168.68.108 SMTP 80 S: 250 2.1.5 Ok
 3699 1664.416887 192.168.68.108 → 192.168.68.111 SMTP 72 C: DATA
 3700 1664.416925 192.168.68.111 → 192.168.68.108 SMTP 103 S: 354 End data with <CR><LF>.<CR><LF>
 3701 1664.417109 192.168.68.108 → 192.168.68.111 SMTP 105 C: DATA fragment, 39 bytes
 3702 1664.417109 192.168.68.108 → 192.168.68.111 SMTP 1514 C: DATA fragment, 1448 bytes
 3704 1664.417281 192.168.68.108 → 192.168.68.111 SMTP/IMF 95 from: caleb@thephreaks.com(Caleb), subject: Secure File Transfer,  (text/plain) (application/zip) | .
 3705 1664.418214 192.168.68.111 → 192.168.68.108 SMTP 101 S: 250 2.0.0 Ok: queued as 781252113
 3706 1664.418331 192.168.68.108 → 192.168.68.111 SMTP 72 C: QUIT
 3707 1664.418365 192.168.68.111 → 192.168.68.108 SMTP 81 S: 221 2.0.0 Bye
 3719 1664.803377 204.141.43.44 → 192.168.68.111 SMTP 134 S: 220 mx.zohomail.com SMTP Server ready March 6, 2024 7:23:14 AM PST
 3721 1664.803498 192.168.68.111 → 204.141.43.44 SMTP 90 C: EHLO mailserver-phreak
 3723 1664.977488 204.141.43.44 → 192.168.68.111 SMTP 180 S: 250-mx.zohomail.com Hello mailserver-phreak (cpc111699-linc13-2-0-cust632.12-1.cable.virginm.net (86.5.206.121))
 3724 1664.977966 204.141.43.44 → 192.168.68.111 SMTP 80 S: 250-STARTTLS
 3726 1664.978432 204.141.43.44 → 192.168.68.111 SMTP 80 S: 250-8BITMIME
 3727 1664.978907 204.141.43.44 → 192.168.68.111 SMTP 85 S: 250 SIZE 53477376
 3729 1664.978950 192.168.68.111 → 204.141.43.44 SMTP 76 C: STARTTLS
 3730 1665.168953 204.141.43.44 → 192.168.68.111 SMTP 91 S: 220 Ready to start TLS.
 3765 1784.562487 192.168.68.111 → 192.168.68.108 SMTP 109 S: 220 The Phreaks Mail Server - We run this
 3767 1784.562655 192.168.68.108 → 192.168.68.111 SMTP 88 C: HELO phreak-ubuntu01
 3769 1784.562714 192.168.68.111 → 192.168.68.108 SMTP 89 S: 250 mailserver-phreak
 3770 1784.562821 192.168.68.108 → 192.168.68.111 SMTP 100 C: MAIL FROM:<caleb@thephreaks.com>
 3771 1784.566751 192.168.68.111 → 192.168.68.108 SMTP 80 S: 250 2.1.0 Ok
 3772 1784.567000 192.168.68.108 → 192.168.68.111 SMTP 102 C: RCPT TO:<resources@thetalents.com>
 3773 1784.570214 192.168.68.111 → 192.168.68.108 SMTP 80 S: 250 2.1.5 Ok
 3774 1784.570365 192.168.68.108 → 192.168.68.111 SMTP 72 C: DATA
 3775 1784.570415 192.168.68.111 → 192.168.68.108 SMTP 103 S: 354 End data with <CR><LF>.<CR><LF>
 3776 1784.570600 192.168.68.108 → 192.168.68.111 SMTP 105 C: DATA fragment, 39 bytes
 3778 1784.612987 192.168.68.108 → 192.168.68.111 SMTP/IMF 1507 from: caleb@thephreaks.com(Caleb), subject: Secure File Transfer,  (text/plain) (application/zip) | .
 3780 1784.615089 192.168.68.111 → 192.168.68.108 SMTP 101 S: 250 2.0.0 Ok: queued as 9D8AB2113
 3781 1784.615317 192.168.68.108 → 192.168.68.111 SMTP 72 C: QUIT
 3782 1784.615498 192.168.68.111 → 192.168.68.108 SMTP 81 S: 221 2.0.0 Bye
 3793 1784.998336 204.141.43.44 → 192.168.68.111 SMTP 134 S: 220 mx.zohomail.com SMTP Server ready March 6, 2024 7:25:14 AM PST
 3795 1784.998477 192.168.68.111 → 204.141.43.44 SMTP 90 C: EHLO mailserver-phreak
 3797 1785.175585 204.141.43.44 → 192.168.68.111 SMTP 180 S: 250-mx.zohomail.com Hello mailserver-phreak (cpc111699-linc13-2-0-cust632.12-1.cable.virginm.net (86.5.206.121))
 3798 1785.175586 204.141.43.44 → 192.168.68.111 SMTP 80 S: 250-STARTTLS
 3800 1785.175826 204.141.43.44 → 192.168.68.111 SMTP 99 S: 250-8BITMIME | SIZE 53477376
 3801 1785.175865 192.168.68.111 → 204.141.43.44 SMTP 76 C: STARTTLS
 3802 1785.350765 204.141.43.44 → 192.168.68.111 SMTP 91 S: 220 Ready to start TLS.
 3851 1904.753668 192.168.68.111 → 192.168.68.108 SMTP 109 S: 220 The Phreaks Mail Server - We run this
 3853 1904.753892 192.168.68.108 → 192.168.68.111 SMTP 88 C: HELO phreak-ubuntu01
 3855 1904.753950 192.168.68.111 → 192.168.68.108 SMTP 89 S: 250 mailserver-phreak
 3856 1904.754094 192.168.68.108 → 192.168.68.111 SMTP 100 C: MAIL FROM:<caleb@thephreaks.com>
 3857 1904.756561 192.168.68.111 → 192.168.68.108 SMTP 80 S: 250 2.1.0 Ok
 3858 1904.756794 192.168.68.108 → 192.168.68.111 SMTP 102 C: RCPT TO:<resources@thetalents.com>
 3859 1904.759379 192.168.68.111 → 192.168.68.108 SMTP 80 S: 250 2.1.5 Ok
 3860 1904.759575 192.168.68.108 → 192.168.68.111 SMTP 72 C: DATA
 3861 1904.759626 192.168.68.111 → 192.168.68.108 SMTP 103 S: 354 End data with <CR><LF>.<CR><LF>
 3862 1904.759837 192.168.68.108 → 192.168.68.111 SMTP 105 C: DATA fragment, 39 bytes
 3864 1904.800798 192.168.68.108 → 192.168.68.111 SMTP/IMF 1465 from: caleb@thephreaks.com(Caleb), subject: Secure File Transfer,  (text/plain) (application/zip) | .
 3866 1904.802084 192.168.68.111 → 192.168.68.108 SMTP 101 S: 250 2.0.0 Ok: queued as CBB0C2113
 3867 1904.802250 192.168.68.108 → 192.168.68.111 SMTP 72 C: QUIT
 3868 1904.802343 192.168.68.111 → 192.168.68.108 SMTP 81 S: 221 2.0.0 Bye
 3879 1905.181173 204.141.43.44 → 192.168.68.111 SMTP 134 S: 220 mx.zohomail.com SMTP Server ready March 6, 2024 7:27:15 AM PST
 3881 1905.181287 192.168.68.111 → 204.141.43.44 SMTP 90 C: EHLO mailserver-phreak
 3883 1905.353646 204.141.43.44 → 192.168.68.111 SMTP 180 S: 250-mx.zohomail.com Hello mailserver-phreak (cpc111699-linc13-2-0-cust632.12-1.cable.virginm.net (86.5.206.121))
 3884 1905.354142 204.141.43.44 → 192.168.68.111 SMTP 80 S: 250-STARTTLS
 3886 1905.354655 204.141.43.44 → 192.168.68.111 SMTP 99 S: 250-8BITMIME | SIZE 53477376
 3887 1905.354685 192.168.68.111 → 204.141.43.44 SMTP 76 C: STARTTLS
 3888 1905.524950 204.141.43.44 → 192.168.68.111 SMTP 91 S: 220 Ready to start TLS
```


Several SMTP conversations were discovered.

To identify the TCP streams:

```bash
tshark -r phreaky.pcap -Y smtp -T fields -e tcp.stream | sort -nu
```
<img width="1887" height="757" alt="image" src="https://github.com/user-attachments/assets/7de7159d-b8b5-4511-90ec-ef3a9bad715e" />

Output:

```
1
2
3
...
31
```
---

# Exporting Emails

Since the traffic consisted of SMTP messages, the emails were exported directly from the capture.

```bash
mkdir mails
tshark -r phreaky.pcap --export-objects imf,mails
```
<img width="1865" height="962" alt="image" src="https://github.com/user-attachments/assets/35251296-70fb-4581-a125-cb5fee9ecb10" />
<img width="1610" height="127" alt="image" src="https://github.com/user-attachments/assets/5f2fb355-bb59-49b7-92e4-555b01375196" />


This produced multiple `.eml` files named:

```
Secure File Transfer.eml
Secure File Transfer(1).eml
...
Secure File Transfer(14).eml
```

---

# Extracting Attachments

Each email contained:

* A password
* A password-protected ZIP attachment

The following Python script was used to extract every attachment.

```python
import os
import email

os.makedirs("attachments", exist_ok=True)

for fn in os.listdir("mails"):
    with open(os.path.join("mails", fn), "rb") as f:
        msg = email.message_from_binary_file(f)

    for part in msg.walk():
        if part.get_filename():
            with open(os.path.join("attachments", part.get_filename()), "wb") as out:
                out.write(part.get_payload(decode=True))
```

---

# Inspecting the ZIP Files

Listing every archive revealed that each ZIP contained one part of a split PDF.

```bash
for z in attachments/*.zip; do
    7z l "$z"
done
```

<img width="1843" height="925" alt="image" src="https://github.com/user-attachments/assets/18f6ddcc-ae07-473e-8905-e7b1161257bf" />

<img width="1802" height="133" alt="image" src="https://github.com/user-attachments/assets/a7091b79-3d75-45e7-9376-3edfffcd0917" />


Example:

```
phreaks_plan.pdf.part1
phreaks_plan.pdf.part2
...
phreaks_plan.pdf.part15
```

---

# Recovering the Passwords

Every email included a line similar to:

```
Password: S3W8yzixNoL8
```

Each password corresponded to the ZIP attachment contained in the same email.

---

# Extracting the Split PDF

Using the password found inside each email, every archive was extracted.

Example:

```bash
7z x attachment.zip -pPASSWORD
```
This will output the relationship between each message, the password, and the ZIP filename:
```python
python3 - <<'PY'
import os,email

for fn in sorted(os.listdir("mails")):
    path=os.path.join("mails",fn)
    with open(path,"rb") as f:
        msg=email.message_from_binary_file(f)

    pwd=None
    zipname=None

    for part in msg.walk():
        if part.get_content_type()=="text/plain":
            txt=part.get_payload(decode=True).decode(errors="ignore")
            if "Password:" in txt:
                pwd=txt.split("Password:")[1].strip()

        if part.get_filename():
            zipname=part.get_filename()

    print(f"{fn}\t{pwd}\t{zipname}")
PY
```

<img width="1247" height="590" alt="image" src="https://github.com/user-attachments/assets/75a6b7a4-d80c-477d-b979-55b7e2cdc2a2" />

This script will do everything automatically:

```python
python3 - <<'PY'
import os
import re
import email
import subprocess

os.makedirs("parts", exist_ok=True)

for eml in sorted(os.listdir("mails")):
    path = os.path.join("mails", eml)

    with open(path, "rb") as f:
        msg = email.message_from_binary_file(f)

    password = None
    zipfile = None

    for part in msg.walk():
        if part.get_content_type() == "text/plain":
            txt = part.get_payload(decode=True).decode(errors="ignore")
            m = re.search(r'Password:\s*([A-Za-z0-9]+)', txt)
            if m:
                password = m.group(1)

        if part.get_filename():
            zipfile = part.get_filename()

    if password and zipfile:
        zpath = os.path.join("attachments", zipfile)
        print(f"[+] {zipfile}  ->  {password}")
        subprocess.run([
            "7z", "x",
            zpath,
            f"-p{password}",
            "-oparts",
            "-y"
        ])

print("\nDone")
PY
```
<img width="1727" height="927" alt="image" src="https://github.com/user-attachments/assets/1c385fb3-b530-4b46-af9a-87e04575be63" />

After processing all emails, the directory contained:

```
phreaks_plan.pdf.part1
...
phreaks_plan.pdf.part15
```
<img width="1898" height="140" alt="image" src="https://github.com/user-attachments/assets/f4ab6dcc-1f45-481d-a317-c8c4f60d8adb" />

---

# Reconstructing the PDF

The PDF was reconstructed by concatenating all parts in order.

```bash
cat parts/phreaks_plan.pdf.part{1..15} > phreaks_plan.pdf
```

Verification:

```bash
file phreaks_plan.pdf
```
<img width="932" height="82" alt="image" src="https://github.com/user-attachments/assets/eee58719-fe7d-4a84-b5de-c71905a1eefe" />

Output:

```
PDF document, version 1.3, 2 page(s)
```

Additional information:

```bash
pdfinfo phreaks_plan.pdf
```
<img width="1007" height="361" alt="image" src="https://github.com/user-attachments/assets/36e505f3-ffeb-4d48-8694-e320ad0e9af0" />

Output:

```
Pages:      2
Encrypted:  no
PDF version: 1.3
```

---

# Reading the PDF

The document contents were extracted using:

```bash
pdftotext phreaks_plan.pdf -
```
<img width="1845" height="906" alt="image" src="https://github.com/user-attachments/assets/1d8039bb-3183-4281-96ec-f1ac9aa51bd7" />

or viewed directly with any PDF reader.

The recovered document revealed the information required to solve the challenge.

---

# Conclusion

This challenge focused on:

* SMTP traffic analysis
* Exporting IMF email objects
* MIME attachment extraction
* Password-protected ZIP archives
* Reconstructing split files
* PDF forensic analysis

The solution involved extracting each email, recovering the attachment passwords, rebuilding the split PDF, and reading the recovered document to obtain the challenge answer.

### About the Author

Mohammed Ali Cybersecurity student focused on penetration testing and Digital Forensics.
accounts on insta

Instagram : https://www.instagram.com/e6ecx/
THM : https://tryhackme.com/p/eng.mohammed.ali.abd

Follow My Journey
I regularly share write-ups and my cybersecurity journey. More content coming soon

