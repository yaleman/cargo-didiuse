use test_implementation::AnotherStruct;

pub fn main() {
    println!("Hello, world!");
    let structname = AnotherStruct;

    structname.dot_broken();

    AnotherStruct::broken();
}
