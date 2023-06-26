use std::io;
/* jctf{n0_vM_just_plain_0ld_ru5tb3rry_ch4ll} */
fn check(inp: String) -> String {
    let b = vec![9usize, 2, 19, 5, 27, 13, 29, 26, 21,
        51, 26, 9, 20, 18, 19, 26, 15, 11, 0,
        8, 13, 26, 29, 11, 3, 26, 17, 20, 34,
        19, 1, 32, 17, 17, 24, 26, 2, 7, 33, 11, 11, 28, 255];
    let a: String = "abcdefghijklmnopqrstuvwxyz_{}0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_string();

    let v = inp
        .bytes()
        .map(|x| a.bytes().position(|y| y == x).unwrap_or(255))
        .collect::<Vec<usize>>();
    match v.eq(&b) {
        | true => "correctly".to_string(),
        | false => "incorrectly".to_string()
    }
}
fn main() -> io::Result<()> {
    println!("Give me the flag? ");
    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer)?;
    let result = check(buffer);
    println!("You've entered {result}");
    Ok(())
}
