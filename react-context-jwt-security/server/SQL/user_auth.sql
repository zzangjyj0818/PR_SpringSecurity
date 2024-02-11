DROP TABLE IF EXISTS user_auth;

CREATE TABLE `user_auth` (
    auth_no int not null AUTO_INCREMENT,
    user_id varchar(100) not null,
    auth varchar(100) not null,
    primary key(auth_no)
);

INSERT INTO user_auth( user_id, auth )
values ('user', 'ROLE_USER');


INSERT INTO user_auth( user_id, auth )
values ('admin', 'ROLE_USER');


INSERT INTO user_auth( user_id, auth )
values ('admin', 'ROLE_ADMIN');