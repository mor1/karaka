--
-- Karaka Skype-XMPP Gateway: SQL schema
--
-- Copyright 2008-2009 Vipadia Ltd
-- Richard Mortier <mort@vipadia.com>
--

DROP DATABASE IF EXISTS karaka;
CREATE DATABASE karaka;
USE karaka;

-- registered skype users in system.
CREATE TABLE registrations
(
        userjid VARCHAR(256) UNICODE NOT NULL,
        user    VARCHAR(256) UNICODE NOT NULL,
        secret  VARCHAR(512) UNICODE NOT NULL,

        PRIMARY KEY (userjid)
);

-- call detail records
CREATE TABLE log
(
        userjid     VARCHAR(256) UNICODE  NOT NULL,
        skypehandle VARCHAR(256) UNICODE  NOT NULL,   
        at          BIGINT       UNSIGNED NOT NULL,
        event       ENUM('start','stop','error') NOT NULL,
        message     VARCHAR(256) UNICODE
);

