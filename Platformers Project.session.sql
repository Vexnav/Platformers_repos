CREATE TABLE user (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(20) UNIQUE NOT NULL,
    email VARCHAR(120) UNIQUE NOT NULL,
    password VARCHAR(200) NOT NULL,
    theme VARCHAR(10) DEFAULT 'Light',
    notifications BOOLEAN DEFAULT TRUE,
    is_confirmed BOOLEAN DEFAULT FALSE,
    profile_image VARCHAR(120) DEFAULT 'default.jpg'
);

CREATE TABLE admin (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(200) NOT NULL
);

CREATE TABLE category (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) UNIQUE NOT NULL
);

CREATE TABLE location (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) UNIQUE NOT NULL
);

CREATE TABLE lost_item (
    id INT PRIMARY KEY AUTO_INCREMENT,
    item_name VARCHAR(100) NOT NULL,
    description TEXT NOT NULL,
    category_id INT NOT NULL,
    location_id INT NOT NULL,
    date_lost DATE NOT NULL,
    image VARCHAR(200),
    status VARCHAR(50) DEFAULT 'Lost',
    FOREIGN KEY (category_id) REFERENCES category(id),
    FOREIGN KEY (location_id) REFERENCES location(id)
);

CREATE TABLE found_item (
    id INT PRIMARY KEY AUTO_INCREMENT,
    item_name VARCHAR(100) NOT NULL,
    description TEXT NOT NULL,
    category_id INT NOT NULL,
    location_id INT NOT NULL,
    date_found DATE NOT NULL,
    image VARCHAR(200),
    status VARCHAR(50) DEFAULT 'Unclaimed',
    FOREIGN KEY (category_id) REFERENCES category(id),
    FOREIGN KEY (location_id) REFERENCES location(id)
);

CREATE TABLE review (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    rating INT NOT NULL,
    comment TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES user(id)
);

CREATE TABLE claim (
    id INT PRIMARY KEY AUTO_INCREMENT,
    item_id INT NOT NULL,
    item_type VARCHAR(50) NOT NULL,
    claimed_by INT NOT NULL,
    proof_of_ownership VARCHAR(200),
    date_claimed DATETIME DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50) DEFAULT 'Pending',
    FOREIGN KEY (claimed_by) REFERENCES user(id)
);

CREATE TABLE matched_item (
    id INT PRIMARY KEY AUTO_INCREMENT,
    lost_item_id INT NOT NULL,
    found_item_id INT NOT NULL,
    date_matched DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (lost_item_id) REFERENCES lost_item(id),
    FOREIGN KEY (found_item_id) REFERENCES found_item(id)
);
