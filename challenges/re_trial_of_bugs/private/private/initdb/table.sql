CREATE TABLE games (
    game_id SERIAL PRIMARY KEY,
    game_token VARCHAR(32) NOT NULL,
    data BYTEA NOT NULL
);

CREATE TABLE game_chunks (
    game_id INTEGER NOT NULL REFERENCES games ON DELETE CASCADE,
    world_name VARCHAR(64) NOT NULL,
    x INTEGER NOT NULL,
    y INTEGER NOT NULL,
    volatile BOOLEAN NOT NULL,
    data BYTEA NOT NULL,

    PRIMARY KEY (game_id, world_name, x, y, volatile)
);
