DROP TABLE IF EXISTS user;

CREATE TABLE `user` (
    `NO` int not null auto_increment,
    `USER_ID` varchar(100) NOT NULL,
    `USER_PW` varchar(200) NOT NULL,
    `NAME` varchar(100) NOT NULL,
    `EMAIL` varchar(200) DEFAULT NULL,
    `REG_DATE` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `UPD_DATE` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `ENABLED` int default 1,
    PRIMARY KEY (`NO`)
) COMMENT ='회원';

INSERT INTO user (user_id, user_pw, name, email)
VALUES ('user', '$2a$12$TrN..KcVjciCiz.5Vj96YOBljeVTTGJ9AUKmtfbGpgc9hmC7BxQ92'
       , '사용자', 'user@mail.com');

INSERT INTO user (user_id, user_pw, name, email)
VALUES ('admin', '$2a$12$TrN..KcVjciCiz.5Vj96YOBljeVTTGJ9AUKmtfbGpgc9hmC7BxQ92'
    ,'관리자', 'admin@mail.com');