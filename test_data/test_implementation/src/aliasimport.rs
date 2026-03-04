// this should be flagged
use vulnerablepackage as vuln2;

pub fn test_alias_import() {
    println!("Testing the alias import...");
    vuln2::ExampleStruct::broken();
}
