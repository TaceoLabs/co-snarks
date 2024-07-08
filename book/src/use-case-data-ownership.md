# Data Ownership

Data per se doesn’t contain much value. Only when data can be combined and computed on, value is created. With handling data, tough, comes responsibility. Data protection rights around the globe are getting stricter exposing data processors to regulatory risks.

Instead of handling data in plain, co-SNARKs can be used to perform computations on encrypted (secret shared) data only. As seen [in the case of Worldcoin](https://de-de.worldcoin.org/blog/announcements/worldcoin-foundation-unveils-new-smpc-system-deletes-old-iris-codes), which handles highly sensitive data in the form of biometric iris scans, MPC used in co-SNARKs removes the need for storing the data itself. The required computations, namely “is this iris hash already part of the dataset?”, can still be performed.

Data can remain in user’s control, while still contribute to economic activities by computing on this data. co-SNARKS enable composable private onchain state. Our demo application, the [Max Pick Challenge](https://blog.taceo.io/max-pick-challenge), demonstrates how user input is kept private, while still be used and compared in the collaborative guessing game. The highest unique guess can only be determined, when all guesses are compared to each other. However, the game only works if the actual guess is not leaked to the public. With today’s blockchain solution one wouldn’t be able to build such types of applications – co-SNARKs open up an entire new design space for how data can be brought to and use onchain.

