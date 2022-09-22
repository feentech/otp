# otp
Simple library to generate TOTP codes in Rust.

Credit where credit is due I took most (all) of the code from [this](https://github.com/TimDumol/rust-otp) project. All
I did was make the code more ergonomic for my own use.

```
  let totp = otp::Totp::new("JBSWY3DPEHPK3PXP", 30, 0);
  
  // print the current totp value
  println!("{}", totp.now().unwrap());
  
  // check if the provided value is correct
  println!("{}", totp.verify(123456).unwrap());
```
