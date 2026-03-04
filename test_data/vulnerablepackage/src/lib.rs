pub struct ExampleStruct;

impl ExampleStruct {
    pub fn dot_broken(&self) {
        // This function is vulnerable to a memory corruption issue.
        // Do not call this function in production code.
        println!("This does bad things!");
    }

    pub fn broken() {
        // This function is vulnerable to a memory corruption issue.
        // Do not call this function in production code.
        println!("This does bad things!");
    }

    pub fn not_broken() {
        // This function is safe to call.
        println!("This does not do bad things!");
    }
}
