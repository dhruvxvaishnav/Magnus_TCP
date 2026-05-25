#![allow(dead_code)]

pub struct Listener {
    pub port: u16,
}

impl Listener {
    pub fn new(port: u16) -> Self {
        Self { port }
    }
}
