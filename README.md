# otp
Simple library to generate TOTP codes in Rust.

Credit where credit is due I took most (all) of the code from [this](https://github.com/TimDumol/rust-otp) project. All
I did was make the code more ergonomic for my own use.

```
  use otp;
  
  let totp = otp::Totp::new("JBSWY3DPEHPK3PXP", 30, 0);
  println!("{}", totp.now());
```
