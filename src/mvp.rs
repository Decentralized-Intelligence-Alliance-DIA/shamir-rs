extern crate bitcoin_hashes;
use byteorder;
use std::io::Cursor;
use byteorder::{LittleEndian, WriteBytesExt};
use std::str::FromStr;
use crate::share::{ Share };
use secp256k1_ge::scalar::{ Scalar, self};
use secp256k1_ge::group::{ Ge, Gej };
use secp256k1_ge::group::fe::Fe;
use secp256k1::{Error, Message, Signature, Signing, Verification, PublicKey, Secp256k1, SecretKey };
use bitcoin_hashes::{sha256, Hash};
use crate::sss::*;

const COUNT_OF_NODES: usize = 10;

struct HackGe {
    pub x: Fe,
    pub y: Fe,
    infinity: libc::c_int
}

struct HackFe {
    pub limbs: [u64; 5],
}

fn u64_to_hex (x: &u64)-> String {
    let res = format!("{:x}", x);

    if res.len() == 12 {
        return format!("0{:x}", x);
    }
    res
}

fn u8_to_hex (x: &u8)-> String {
    if x < &16 {
        format!("0{:x}", x)
    }
    else {
        format!("{:x}", x)
    }
}

fn u64_arr_to_hex (x: std::slice::Iter<u64>) -> String {
    
    let mut res = x.clone().map(|y|u64_to_hex(y)).rev().collect::<Vec<String>>().join("").to_ascii_uppercase();
    res.replace_range(0..1, "");
    
    assert!(res.len() == 64); 
    res
}


fn u8_arr_to_hex (x: std::slice::Iter<u8>) -> String {
    x.map(|y|u8_to_hex(y)).collect::<Vec<String>>().join("").to_ascii_uppercase()
}

impl HackGe { 
    fn from_ge(gej: Ge) -> Self {

        let hack_public_d_key: Self = unsafe {
            std::mem::transmute(gej)
        };

        assert!(hack_public_d_key.infinity == 0);

        hack_public_d_key
    }

    fn from_gej(gej: Gej) -> Self {

        let hack_public_d_key: Self = unsafe {
            std::mem::transmute(Ge::from(gej))
        };

        assert!(hack_public_d_key.infinity == 0);

        hack_public_d_key
    }


    fn get_hfe(&self, point: Fe)-> [u64; 5] {

        let hack_public_key_x: HackFe = unsafe {
            std::mem::transmute(point)
        };

        hack_public_key_x.limbs
    }

    pub fn get_x_fe(&self)-> Fe {
        self.x
    }

    pub fn get_y_fe(&self)-> Fe {
        self.y
    }

    pub fn get_x(&self)-> [u64; 5] {
        self.get_hfe(self.x)
    }

    pub fn get_y(&self)-> [u64; 5] {
        self.get_hfe(self.y)
    }
    
    pub fn get_hex(&self) -> String {

        //let x = u8_arr_to_hex_rev(u64_5_to_u8(self.get_x().to_vec()).iter());
        //let y = u8_arr_to_hex_rev(u64_5_to_u8(self.get_y().to_vec()).iter());

        
        let x = u64_arr_to_hex(self.get_x().iter());
        let y = u64_arr_to_hex(self.get_y().iter());


        let res = format!("04{}{}", x, y);

        //if res.len() != 130 {
        //    println!("HEX {:?}", res);
        //    println!("x: {:?}, y: {:?}", x.len(), y.len());
        //    println!("x: {:?}, y: {:?}", self.get_x(), self.get_y());
        //}

        assert!(res.len() == 130);

        res
    }

    pub fn get_public_key(&self) -> bitcoin::PublicKey {
        
        let compressed = secp256k1::PublicKey::from_str(&self.get_hex()).unwrap().serialize();
        let pubkey = bitcoin::PublicKey::from_slice(&compressed).unwrap();
        pubkey
    }

    pub fn get_public_key2(&self) -> PublicKey {
        let compressed = PublicKey::from_str(&self.get_hex()).unwrap().serialize();
        let pubkey = PublicKey::from_slice(&compressed).unwrap();
        pubkey
    }

    pub fn get_address(&self) -> String {
        let pubkey = self.get_public_key();
        use bitcoin::util::address::Address;
        use bitcoin::network::{ constants };
        let network = constants::Network::Bitcoin;
        let address = Address::p2wpkh(&pubkey, network).unwrap();
        address.to_string()
    }
}

impl PartialEq for HackGe {
    fn eq(&self, another: &Self)-> bool {
        self.get_x() == another.get_x() && self.get_y() == another.get_y()
    }
}

impl Eq for HackGe {}

fn scalar_to_u64(sum_secret: Scalar)-> [u64; 4] {
    struct HackScalar {
        pub limbs: [u64; 4]
    }

    let hack_scalar: HackScalar = unsafe {
        std::mem::transmute(sum_secret)
    };

    hack_scalar.limbs

}

fn u64_5_to_u8(sum_secret: Vec<u64>) -> [u8; 40] {
    let mut seckey_array: [u8; 40] = [0;40];
    let mut cur = Cursor::new(&mut seckey_array as &mut [u8]);

    

    for i in 0..5 {
        cur.write_u64::<LittleEndian>(sum_secret[i]).unwrap()
    }

    seckey_array

}


fn scalar_to_u8_32(sum_secret: Scalar) -> [u8; 32] {
    let mut seckey_array: [u8; 32] = [0;32];
    let mut cur = Cursor::new(&mut seckey_array as &mut [u8]);

    let hack_scalar = scalar_to_u64(sum_secret);

    for i in 0..4 {
        cur.write_u64::<LittleEndian>(hack_scalar[i]).unwrap()
    }

    seckey_array.reverse();
    seckey_array

}

fn verify<C: Verification>(secp: &Secp256k1<C>, msg: &[u8], sig: [u8; 64], pubkey: PublicKey) -> Result<bool, Error> {
    let msg2 = sha256::Hash::hash(msg);
    
    let msg3 = Message::from_slice(&msg2)?;
    let sig = Signature::from_compact(&sig)?;

    Ok(secp.verify(&msg3, &sig, &pubkey).is_ok())
}

fn sign<C: Signing>(secp: &Secp256k1<C>, msg: &[u8], seckey: [u8; 32]) -> Result<Signature, Error> {
    let msg = sha256::Hash::hash(msg);
    let msg = Message::from_slice(&msg)?;
    let seckey = SecretKey::from_slice(&seckey)?;
    Ok(secp.sign(&msg, &seckey))
}

fn get_public_key(private_key: &Scalar) -> Gej {
    let mut gej = Gej::default();
    gej.scalar_base_mul(&private_key);
    gej
}


fn get_distributed_public_key<'a, I>(shares: I)-> Gej
where
    I: Iterator<Item = &'a Share> + Clone,
{
    let mut numerator = Scalar::default();
    let mut denominator = Scalar::default();
    let mut tmp = Scalar::default();
    let mut dst = Gej::default();
    
    let indeces = shares.clone().map(|Share { index, .. }| index);

    for Share { index, value } in shares.clone() {

        let mut gej = get_public_key(value);

        eval_lagrange_basis_at_zero_in_place(
            &mut tmp,
            index,
            indeces.clone(),
            &mut numerator,
            &mut denominator,
        );
        
        gej.scalar_mul_assign(&tmp);
        dst.add_assign(&gej);
        
    }
    dst
}

fn get_base_point() -> Ge {
    let mut ge = Ge::default();
    ge.scalar_base_mul(&Scalar::one());
    ge
}

       
fn fe_to_scalar(fe: Fe)-> Scalar {
    let mut b32  = [0; 32];
    let mut fe1 = fe.clone();
    fe1.normalize();
    fe1.put_b32(&mut b32);
    let mut msg_scalar = Scalar::default();
    msg_scalar.set_b32(&b32);
    msg_scalar
}

fn msg_to_scalar(msg: &[u8])-> Scalar {
    let msg = sha256::Hash::hash(&msg);
    let mut msg_scalar = Scalar::default();
    //410de92118775c11d0ff1334390cfde885ad4bfac0f737af3aa92006e6b8bf9e
    msg_scalar.set_b32(&msg);
    msg_scalar
}


fn test_secret (secrets: Vec<Scalar>, sum_shares: Vec<Share>, threshold: usize) {
    let mut sum_secret = Scalar::default();

    for i in 0..COUNT_OF_NODES {
        sum_secret.add_assign_mut(&secrets[i]);
    }

    let seckey_array = scalar_to_u8_32(sum_secret);

    let secp = Secp256k1::new();

    let msg = b"0479BE667EF9DCBB0479BE667EF9DCBB";

    let signature = sign(&secp, msg, seckey_array).unwrap();

    let base_skey = libsecp256k1::SecretKey::parse(&[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]).unwrap();
    let base_pkey = libsecp256k1::PublicKey::from_secret_key(&base_skey);
    let base_pkey_ser = base_pkey.serialize();
    
    assert!("0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8" == u8_arr_to_hex(base_pkey_ser.to_vec().iter()));
    
    let skey = libsecp256k1::SecretKey::parse(&seckey_array).unwrap();
    let pkey = libsecp256k1::PublicKey::from_secret_key(&skey);
    let pub_from_secret_hex = u8_arr_to_hex(pkey.serialize().to_vec().iter());
    let message = libsecp256k1::Message::parse(&msg);

    let (sig, recid) = libsecp256k1::sign(&message, &skey);

    //println!("{:?}", sig);
    // Self verify
    assert!(libsecp256k1::verify(&message, &sig, &pkey));

    let base_seckey = SecretKey::from_str("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
    let base_pubkey = PublicKey::from_secret_key(&secp, &base_seckey);
    let base_pubkey2 = PublicKey::from_str("0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8").unwrap();
    assert!(base_pubkey2 == base_pubkey);

    
    

    let never_used_secret_key = SecretKey::from_slice(&seckey_array).unwrap();
    let never_used_public_key = PublicKey::from_secret_key(&secp, &never_used_secret_key);
    let public_d_key = get_distributed_public_key(sum_shares.iter());

    //println!("PUB KEY LEN {:?}", _pubkey.());

    let public_key = get_public_key(&sum_secret);

    
       
    assert!(public_d_key.eq(&public_key));
    assert!(public_key.eq(&public_d_key));

    assert!(HackGe::from_gej(public_d_key) == HackGe::from_gej(public_key));

    
    let public_d_key_ge = Ge::from(public_d_key);
    let public_key_ge = Ge::from(public_key);

    
    //println!("ARR MATCH {:?} - Len {:?}", pkey.serialize().to_vec(), pkey.serialize().to_vec().len());
    //println!("ARR MATCH {:?}", public_key_ge);


    assert!(public_d_key_ge.is_valid_var());
    assert!(public_key_ge.is_valid_var());

    assert!(!public_d_key_ge.is_infinity());
    assert!(!public_key_ge.is_infinity());

    let public_d_key_ge2 = Gej::from(public_d_key_ge);
    let public_key_ge2 = Gej::from(public_key_ge);

    
    
    
    assert!(public_key_ge2.eq(&public_d_key_ge2));
    assert!(public_d_key_ge2.eq(&public_key_ge2));

    assert!(public_key_ge2.eq(&public_key));
    assert!(public_d_key_ge2.eq(&public_d_key));

    assert!(HackGe::from_gej(public_d_key).get_hex() == HackGe::from_gej(public_key).get_hex());

    print!("{:?}", public_d_key);
    print!("DEBUG {:?} / {:?}", pub_from_secret_hex, HackGe::from_gej(public_d_key).get_hex());
    assert!(pub_from_secret_hex == HackGe::from_gej(public_d_key).get_hex());
    assert!(pub_from_secret_hex == HackGe::from_gej(public_key).get_hex());
    

    //assert!(HackGe::from_gej(public_d_key).get_public_key() == HackGe::from_gej(public_key).get_public_key());
    //println!("FROM_POINT {:?}, FROM_SECRET {:?}", HackGe::from_gej(public_d_key).get_public_key2(), never_used_public_key);
    assert!(HackGe::from_gej(public_d_key).get_public_key2() == never_used_public_key);
    

    let serialize_sig = signature.serialize_compact();
    //println!("SIG: {:?}", u8_arr_to_hex(serialize_sig.iter()));
    
    assert!(verify(&secp, msg, serialize_sig, never_used_public_key).unwrap());


    assert!(shares_are_k_consistent_with_secret(
        &sum_shares,
        &sum_secret,
        threshold
    ));
}

fn get_shares_protocol_rng (indeces: Vec<Scalar>, threshold: usize, is_secret: bool)-> Vec<Share> {
    //random numbers of each node
    let mut secrets = [Scalar::default(); COUNT_OF_NODES];
    scalar::randomise_scalars_using_thread_rng(&mut secrets);

    //shares of each node
    let mut shares = Vec::with_capacity(COUNT_OF_NODES);
    shares.resize(COUNT_OF_NODES, Vec::default());

    //filled shares of each nodes
    for i in 0..COUNT_OF_NODES {
        shares[i] = share_secret(&indeces, &secrets[i], threshold);
    }

    let mut sum_shares = [Share::default(); COUNT_OF_NODES];
       
       for i in 0..COUNT_OF_NODES {
           for j in 0..COUNT_OF_NODES {
               sum_shares[i].add_assign_improved(&shares[j][i]);    
           }
       }
    
    if is_secret {
        test_secret(secrets.to_vec(), sum_shares.to_vec(), threshold);
    }

    //let public_d_key = get_distributed_public_key(shares_of_secret_key.iter());

    sum_shares.to_vec()


}


fn mul_shares(shares_of_secret_key: Vec<Share>, shares_of_nonce: Vec<Share>)-> Vec<Share> {
    let mut new_shares = Vec::with_capacity(COUNT_OF_NODES);
    //new_shares.resize(COUNT_OF_NODES, Share::default());
    for Share { index: index1, value: secret_key } in shares_of_secret_key.clone() {
        for Share { index: index2, value: nonce } in shares_of_nonce.clone() {
            //shares_of_nonce
            if index1 == index2 {
                let mut sum = Scalar::default();
                sum.mul_mut(&nonce, &secret_key);
                let mut share = Share::default();
                share.index = index1;
                share.value = sum;
                new_shares.push(share);

            }
        }
    }
    new_shares
} 

fn add_shares(shares_of_secret_key: Vec<Share>, shares_of_nonce: Vec<Share>)-> Vec<Share> {
    let mut new_shares = Vec::with_capacity(COUNT_OF_NODES);
    //new_shares.resize(COUNT_OF_NODES, Share::default());
    for Share { index: index1, value: secret_key } in shares_of_secret_key.clone() {
        for Share { index: index2, value: nonce } in shares_of_nonce.clone() {
            //shares_of_nonce
            if index1 == index2 {
                let mut sum = Scalar::default();
                sum.add_mut(&nonce, &secret_key);
                let mut share = Share::default();
                share.index = index1;
                share.value = sum;
                new_shares.push(share);

            }
        }
    }
    new_shares
} 

fn distributed_inverse(shares: Vec<Share>, threshold: usize)-> Vec<Share> {
    
    let result = get_shares_protocol_rng(shares.iter().map(|x|x.index).collect(), threshold, false);

    let temp_shares = mul_shares(shares.clone(), result.clone());

    let mut temp = interpolate_shares_at_zero(temp_shares.iter());
    
    temp.inverse_assign();

    shares_scale(result, temp)

}

fn shares_scale(shares: Vec<Share>, scale: Scalar)->  Vec<Share> {
    let mut cloned = shares.clone();
    let len = cloned.len();
    for i in 0..len {
        cloned[i].scale_assign(&scale);
    }

    cloned
}

//fn get_shares (n: usize)-> 



#[cfg(test)]
mod tests {
    use super::*;
    

   #[test]
   fn mvp() {


       let mut indeces = [Scalar::default(); COUNT_OF_NODES];
       scalar::randomise_scalars_using_thread_rng(&mut indeces);
       
       let threshold = 3;
       
       let shares_of_secret_key = get_shares_protocol_rng(indeces.to_vec(), threshold, true);


       //START: lets check that we can sign and verify the simple text message with our private key
       let msg = b"0479BE667EF9DCBB0479BE667EF9DCBB";



       let public_d_key = get_distributed_public_key(shares_of_secret_key.iter());
       
       let public_d_key_ge = Ge::from(public_d_key);
       
       //check base point
       //9817f8165b81f259d928ce2ddbfc9b02070b87ce9562a055acbbdcf97e66be79b8d410fb8fd0479c195485a648b417fda808110efcfba45d65c4a32677da3a48
       let base_public_key = "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";

       

       let base_point_hex = HackGe::from_ge(get_base_point()).get_hex();
       assert!(base_point_hex == base_public_key);
       let base_addr = HackGe::from_ge(get_base_point()).get_address();
       //println!("base address {:?}", base_addr);
       let base_public_key2 = HackGe::from_ge(get_base_point()).get_public_key2();
       //println!("base public key {:?}", base_public_key2);
       
       //let base_public_key = HackGe::from_ge(get_base_point()).get_public_key2()
       let public_d_key_hex = HackGe::from_ge(public_d_key_ge).get_hex();
       //let public_key_hex = HackGe::from_ge(public_key_ge).get_hex();

       //uncompressed public key 04 + x + y
       //assert!(public_d_key_hex == public_key_hex);

       
       //assert!(String::from(base_public_key).len() == 130);
       //TODO: check why sometimes 129
       //assert!(String::from(public_d_key_hex).len() == 130);
       
       assert!(bitcoin::PublicKey::from_str(&base_public_key).is_ok());
       assert!(PublicKey::from_str(&base_public_key).is_ok());
       
       
       //let addr = HackGe::from_ge(public_key_ge).get_address();
       //println!("{:?}", addr);
       
       //PUBLIC KEY IS CREATED!

       //SIGN MESSAGE
       //let b = sha256::Hash::hash("Hello world!".as_bytes());
       //let m2 = Message::from(b);
       //println!("{:?}", m2);
       let msg = msg_to_scalar(msg);

       let shares_of_nonce = get_shares_protocol_rng(indeces.to_vec(), threshold, false);

       for i in 0..shares_of_nonce.len() {
            assert!(shares_of_nonce[i] != Share::default());
       }
       

       let nonce_public_key_gej = get_distributed_public_key(shares_of_nonce.iter());
       
       //assert!(nonce_public_key_gej != Gej::default());
       
       let nonce_public_key_ge = Ge::from(nonce_public_key_gej);

       let nonce_public_key_x = HackGe::from_ge(nonce_public_key_ge).get_x_fe();
       let nonce_public_key_x_scalar = fe_to_scalar(nonce_public_key_x);

       assert!(nonce_public_key_x_scalar != Scalar::default());
       
       let result = distributed_inverse(shares_of_nonce, threshold);

       assert!(result.len() == COUNT_OF_NODES);
       for i in 0..result.len() {
         assert!(result[i] != Share::default());
       }

       let temp = shares_scale(shares_of_secret_key, nonce_public_key_x_scalar);
    
       assert!(temp.len() == COUNT_OF_NODES);
       for i in 0..temp.len() {
          assert!(temp[i] != Share::default());
       }
    
       let shares_of_message = share_secret(&indeces, &msg, threshold);
       
       assert!(shares_of_message.len() == COUNT_OF_NODES);
       for i in 0..shares_of_message.len() {
          assert!(shares_of_message[i] != Share::default());
       }

       let temp_shares = add_shares(temp.clone(), shares_of_message.clone());

       assert!(temp_shares.len() == COUNT_OF_NODES);
       for i in 0..temp_shares.len() {
          assert!(temp_shares[i] != Share::default());
       }
       
       let shares_of_signature = mul_shares(temp_shares.clone(), result.clone());

       assert!(shares_of_signature.len() == COUNT_OF_NODES);
       for i in 0..shares_of_signature.len() {
          assert!(shares_of_signature[i] != Share::default());
       }

       let partial_signature = interpolate_shares_at_zero(shares_of_signature.iter());

       assert!(partial_signature != Scalar::default());


       //let partial_signature_hex = to_hex_u64(scalar_to_u64(partial_signature).iter());

       //let nonce_public_key_x_scalar_hex = to_hex_u64(scalar_to_u64(nonce_public_key_x_scalar).iter());

       

       let mut a = scalar_to_u8_32(nonce_public_key_x_scalar).to_vec();
       a.extend(scalar_to_u8_32(partial_signature).to_vec());
       

       let sig = Signature::from_compact(&a).unwrap();
       //sig.normalize_s();
       //println!("SIG: {:?}", sig);
       
       
       
       //println!("PUB: {:?}", HackGe::from_gej(public_d_key).get_public_key2());
       //let der = sig.serialize_der();
       //println!("{:?}", der);

       //let message = libsecp256k1::Message::parse(&b"0479BE667EF9DCBB0479BE667EF9DCBB");

       //let pkey = HackGe::from_gej(public_d_key).get_public_key3();
   
       //let sig = libsecp256k1::Signature::parse_slice(&a).unwrap();
       // Self verify
       //assert!(libsecp256k1::verify(&message, &sig, &pkey));

       assert!(Secp256k1::new().verify
            (
                &Message::from_slice(&sha256::Hash::hash(b"0479BE667EF9DCBB0479BE667EF9DCBB")).unwrap(), 
                &sig, 
                &HackGe::from_gej(public_d_key).get_public_key2()
            ).is_ok());
       println!("WORKS!");
       //let der = sig.serialize_der();
       //assert!(der.len() == 40);
       //assert!(der.capacity() == 72);
       //println!("{:?}", der.capacity());
       
       //let signature = format!("{}{}", nonce_public_key_x_scalar_hex, partial_signature_hex).to_ascii_uppercase();
       
       //0000C6EC59D7C4A1FDE9B15D86E7D8C3117269916B9F1AABAD87F2E5DA5C119FAC37

       //let bar = signature.as_bytes().len();

       //println!("{:?}", bar);
       

       //println!("{:?}", signature);
       //nonce_public_key_x_scalar

       //ANSWER IS "nonce_public_key_x_scalar partial_signature"

       //shares_of_secret_key

       



       //let group_signature = group_sign(&secp, msg).unwrap();

       //let group_serialize_sig = group_signature.serialize_compact();

       //assert!(verify(&secp, msg, group_serialize_sig, _pubkey).unwrap());

       //assert!(group_signature == signature);
       
   }
}