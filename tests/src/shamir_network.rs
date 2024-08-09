use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bytes::Bytes;
use mpc_core::protocols::shamir::network::ShamirNetwork;
use std::sync::mpsc::{self, Receiver, Sender};
use std::{cmp::Ordering, collections::HashMap};

pub struct ShamirTestNetwork {
    num_parties: usize,
    sender: HashMap<(usize, usize), Sender<Bytes>>,
    receiver: HashMap<(usize, usize), Receiver<Bytes>>,
}

impl ShamirTestNetwork {
    pub fn new(num_parties: usize) -> Self {
        // AT Most 1 message is buffered before they are read so this should be fine
        let mut sender = HashMap::with_capacity(num_parties * (num_parties - 1));
        let mut receiver = HashMap::with_capacity(num_parties * (num_parties - 1));

        for sender_id in 0..num_parties {
            for mut receiver_id in 0..num_parties - 1 {
                if receiver_id >= sender_id {
                    receiver_id += 1;
                }
                let (s, r) = mpsc::channel();
                sender.insert((sender_id, receiver_id), s);
                receiver.insert((sender_id, receiver_id), r);
            }
        }

        Self {
            num_parties,
            sender,
            receiver,
        }
    }

    pub fn get_party_networks(mut self) -> Vec<PartyTestNetwork> {
        let mut res = Vec::with_capacity(self.num_parties);

        for partyid in 0..self.num_parties {
            let mut send = Vec::with_capacity(self.num_parties - 1);
            let mut recv = Vec::with_capacity(self.num_parties - 1);

            for mut other_party in 0..self.num_parties - 1 {
                if other_party >= partyid {
                    other_party += 1;
                }

                let s = self.sender.remove(&(partyid, other_party)).unwrap();
                let r = self.receiver.remove(&(other_party, partyid)).unwrap();

                send.push(s);
                recv.push(r);
            }
            let network = PartyTestNetwork {
                id: partyid,
                num_parties: self.num_parties,
                send,
                recv,
            };
            res.push(network);
        }

        assert!(self.sender.is_empty());
        assert!(self.receiver.is_empty());

        res
    }
}

pub struct PartyTestNetwork {
    id: usize,
    num_parties: usize,
    send: Vec<Sender<Bytes>>,
    recv: Vec<Receiver<Bytes>>,
}

impl ShamirNetwork for PartyTestNetwork {
    fn get_id(&self) -> usize {
        self.id
    }

    fn get_num_parties(&self) -> usize {
        self.num_parties
    }

    fn send_many<F: CanonicalSerialize>(
        &mut self,
        mut target: usize,
        data: &[F],
    ) -> std::io::Result<()> {
        if target >= self.num_parties || target == self.id {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("No channel found for party id={}", target),
            ));
        }
        if target > self.id {
            // to get index for the Vec
            target -= 1;
        }

        let size = data.serialized_size(ark_serialize::Compress::No);
        let mut to_send = Vec::with_capacity(size);
        data.serialize_uncompressed(&mut to_send).unwrap();

        self.send[target]
            .send(Bytes::from(to_send))
            .expect("can send");

        Ok(())
    }

    fn recv_many<F: CanonicalDeserialize>(&mut self, mut from: usize) -> std::io::Result<Vec<F>> {
        if from >= self.num_parties || from == self.id {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("No channel found for party id={}", from),
            ));
        }
        if from > self.id {
            // to get index for the Vec
            from -= 1;
        }
        let data = Vec::from(self.recv[from].recv().unwrap());
        Ok(Vec::<F>::deserialize_uncompressed(data.as_slice()).unwrap())
    }

    fn broadcast<F: CanonicalSerialize + CanonicalDeserialize + Clone>(
        &mut self,
        data: F,
    ) -> std::io::Result<Vec<F>> {
        // Serialize
        let size = data.serialized_size(ark_serialize::Compress::No);
        let mut ser_data = Vec::with_capacity(size);
        data.to_owned()
            .serialize_uncompressed(&mut ser_data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        let send_data = Bytes::from(ser_data);

        // Send
        for send in self.send.iter_mut() {
            send.send(send_data.to_owned()).expect("can send");
        }

        // Receive
        let mut res = Vec::with_capacity(self.num_parties);
        for (other_id, recv) in self.recv.iter_mut().enumerate() {
            if other_id == self.id {
                // Put that in the middle
                res.push(data.to_owned());
            }

            let data = Vec::from(recv.recv().unwrap());
            res.push(F::deserialize_uncompressed(data.as_slice()).unwrap());
        }
        if self.id == self.num_parties - 1 {
            // Put that at the end
            res.push(data.to_owned());
        }

        Ok(res)
    }

    fn broadcast_next<F: CanonicalSerialize + CanonicalDeserialize + Clone>(
        &mut self,
        data: F,
        num: usize,
    ) -> std::io::Result<Vec<F>> {
        // Serialize
        let size = data.serialized_size(ark_serialize::Compress::No);
        let mut ser_data = Vec::with_capacity(size);
        data.to_owned()
            .serialize_uncompressed(&mut ser_data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        let send_data = Bytes::from(ser_data);

        // Send
        for s in 1..num {
            let mut other_id = (self.id + s) % self.num_parties;
            match other_id.cmp(&self.id) {
                Ordering::Greater => other_id -= 1,
                Ordering::Less => {}
                Ordering::Equal => continue,
            }
            self.send[other_id]
                .send(send_data.to_owned())
                .expect("can send");
        }

        // Receive
        let mut res = Vec::with_capacity(num);
        res.push(data.to_owned());
        for r in 1..num {
            let mut other_id = (self.id + self.num_parties - r) % self.num_parties;
            match other_id.cmp(&self.id) {
                Ordering::Greater => other_id -= 1,
                Ordering::Less => {}
                Ordering::Equal => {
                    res.push(data.to_owned());
                    continue;
                }
            }
            let data = Vec::from(self.recv[other_id].recv().unwrap());
            res.push(F::deserialize_uncompressed(data.as_slice()).unwrap());
        }

        Ok(res)
    }
}
