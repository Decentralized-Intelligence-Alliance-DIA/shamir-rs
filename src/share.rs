use secp256k1_ge::scalar::Scalar;

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Share {
    pub index: Scalar,
    pub value: Scalar
}



impl Share {
    pub fn add(&mut self, a: &Share, b: &Share) {
        if a.index != b.index {
            panic!("cannot add shares with different indices")
        }
        self.index = a.index;
        self.value.add_mut(&a.value, &b.value);
    }

    pub fn add_assign(&mut self, a: &Share) {
        if self.index != a.index {
            panic!("cannot add shares with different indices")
        }
        self.value.add_assign_mut(&a.value);
    }

    pub fn add_assign_improved(&mut self, a: &Share) {
        
        if self.index == Scalar::default() {
            self.index = a.index;
        }
        
        if self.index != a.index {
            panic!("cannot add shares with different indices")
        }
        self.value.add_assign_mut(&a.value);
    }

    pub fn scale(&mut self, share: &Share, scalar: &Scalar) {
        self.index = share.index;
        self.value.mul_mut(&share.value, scalar);
    }

    pub fn scale_assign(&mut self, scalar: &Scalar) {
        self.value.mul_assign_mut(scalar);
    }
}