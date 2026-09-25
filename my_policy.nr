POLICY custom_policy {

    RULE allow_ssh {
        IF protocol == TCP
        AND destination_port == 22
        THEN ALLOW;
    }

    RULE block_telnet {
        IF protocol == TCP
        AND destination_port == 23
        THEN DENY;
    }

}