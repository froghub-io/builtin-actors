use {
    bytes::BytesMut,
    derive_more::{Deref, DerefMut},
};

const PAGE_SIZE: usize = 4 * 1024;

#[derive(Clone, Debug, Deref, DerefMut)]
pub struct Memory(BytesMut);

impl Default for Memory {
    fn default() -> Self {
        Self(BytesMut::with_capacity(PAGE_SIZE))
    }
}

impl Memory {
    #[inline]
    pub fn grow(&mut self, size: usize) {
        let cap = self.0.capacity();
        if size > cap {
            let required_pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
            self.0.reserve((PAGE_SIZE * required_pages) - self.0.len());
        }
        self.0.resize(size, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grow() {
        let mut mem = Memory::default();
        mem.grow(PAGE_SIZE * 2 + 1);
        assert_eq!(mem.len(), PAGE_SIZE * 2 + 1);
        assert_eq!(mem.capacity(), PAGE_SIZE * 3);
    }
}
