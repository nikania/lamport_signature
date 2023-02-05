use lamport_signature::LamportSignature;

fn main() {
    let seed = "monte near beast";
    let signature = LamportSignature::generate_key(seed);
    let message = "cucumber";
    println!("public key is {:?}", signature.public);
    println!("message is: {message}");
    let sign = signature.sign(message);
    println!("signature of message is {:?}", sign);
    println!("verification shows: {}", 
        LamportSignature::verify(signature.public, message, sign));

}
