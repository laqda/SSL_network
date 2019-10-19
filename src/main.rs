use crate::equipment::Certificate;

mod equipment;

fn main() {
    let eq1 = equipment::Equipment::new(32);
    let eq2 = equipment::Equipment::new(32);

    let c = Certificate::certify(&eq1, &eq2);

    println!("{:?}", c.0.verify(&eq2.get_public_key()));
}
