use vulnerablepackage::ExampleStruct;

pub fn test_used_as_dot() {
    println!("Testing the used as dot...");
    let e = ExampleStruct;

    e.dot_broken();
}
