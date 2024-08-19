# DeFi

Decentralized Finance (DeFi) is transforming the traditional financial landscape by offering open, permissionless, and transparent services. However, privacy and security remain significant challenges. Public on-chain information relating to a user’s financial records, trade intentions or identity could be misused in a sense that the user ends up with worse terms and economic disadvantages.

For instance, publishing a large limit order on-chain immediately reveals the intention of a user to sell or buy a certain asset in high quantities. Market participants know how to use this new piece of information to their advantage. Traditional finance faced the same issue with public stock markets. As a response they introduced so-called Dark Pools, which keep the price impact for large quantity trades as low as possible by matching trades privately.  

In TradFi Dark Pools work because market participations trust a central entity to run the service. Blockchains aim for getting rid of these types of intermediaries. However, running a Dark Pool via a public Smart Contract would not work, since all sensitive information would immediately be leaked.

We need to make sure that sensitive information (e.g. Limit order: I want to buy 10 BTC @ price $100k) is kept private. Yet, at some point multiple private inputs need to be combined so that a buy order can be matched with a sell order.

co-SNARKs have the ability to compute on multiple, encrypted user inputs, while not leaking any information about the inputs itself. For the example of on-chain Dark Pools, users could submit their desire to trade large quantities in an encrypted form to the MPC network, which processes and match trades with each other. Market participants don't get any information headstart they could use for their very own advantage and users get the best price possible.
