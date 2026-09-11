# campus.nr — Campus network security policy
# NetRule Language Specification v1.0

POLICY campus_security {

    RULE allow_https {
        IF protocol == TCP
        AND destination_port == 443
        THEN ALLOW;
    }

    RULE allow_http {
        IF protocol == TCP
        AND destination_port == 80
        THEN ALLOW;
    }

    RULE block_telnet {
        IF protocol == TCP
        AND destination_port == 23
        THEN DENY;
    }

    RULE log_udp {
        IF protocol == UDP
        THEN LOG;
    }

    RULE block_all_tcp {
        IF protocol == TCP
        THEN DENY;
    }

}

POLICY server_policy {

    RULE allow_ssh_from_trusted {
        IF source_ip == 192.168.1.10
        AND protocol == TCP
        AND destination_port == 22
        THEN ALLOW;
    }

    RULE deny_ssh {
        IF destination_port == 22
        AND protocol == TCP
        THEN DENY;
    }

    RULE allow_web {
        IF protocol == TCP
        AND (destination_port == 80 OR destination_port == 443)
        THEN ALLOW;
    }

}
