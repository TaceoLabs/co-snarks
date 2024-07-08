# Gaming

Blockchain gaming aims to combine the benefits of decentralization and user empowerment with a great in-game experience. The nature of blockchain of being fully transparent and auditable can contribute a lot to fair game designs. However, certain games require a degree of privacy or the game doesn’t work as expected. If an onchain transaction contains the user’s next move it would be accessible by everyone else – including the player’s opponent. If now the game design gives the opponent the chance to respond to the next move before it is fully executed, the first player would have a big disadvantage, essentially leaking the plan to its opponent.

A simple example would be the pen & paper game Battleship. Both players secretly position their battleships onto a grid. Every new round one player “attacks” a position on the opponent’ grid, trying to hit a battleship. If the positioning of the ships would take place via public onchain transactions, all information would already be leaked, and the game couldn’t be played.

As a consequence, information like these must be kept secret, while still being “computable”. co-SNARKs can provide both. The players would secret share the ship positions with the MPC nodes. Every “attack” is also sent to the nodes which compute collaboratively if a ship was hit or not.

From simple pen & paper to highly sophisticated strategy games, co-SNARKs can be the missing piece to boost the creation and adoption of onchain games.
