pub use vulnerablepackage::ExampleStruct as AnotherStruct;

pub mod aliasimport;
pub mod used_as_dot;

pub fn test_broken() {
    println!("Testing the broken function...");
    vulnerablepackage::ExampleStruct::broken();
}

#[test]
fn test_not_broken() {
    println!("Testing the not_broken function...");
    vulnerablepackage::ExampleStruct::not_broken();
    println!("We used it!");
}
