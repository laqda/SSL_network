use shrust::Shell;
use crate::equipment::Equipment;

pub struct EquipmentShell(pub Shell<Equipment>);

impl EquipmentShell {
    pub fn new(eq: Equipment) -> EquipmentShell {
        let mut shell = Shell::new(eq);
        shell.new_command("infos", "Display equipment infos", 0, |_, eq, _args| {
            println!("\n{}", eq);
            Ok(())
        });
        shell.new_command("clear", "Clear shell", 0, |_, _eq, _args| {
            print!("\x1B[2J");
            Ok(())
        });
        EquipmentShell(shell)
    }
}