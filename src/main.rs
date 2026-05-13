mod binary;
mod disasm;
mod ir;
mod analysis;
mod codegen;

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;

use binary::load;
use disasm::Disassembler;
use ir::lift::lift;
use analysis::FunctionAnalysis;
use codegen::generate;

#[derive(Parser, Debug)]
#[command(name = "decomp", about = "x86/x86_64 binary to C decompiler")]
struct Args {
    /// Input binary file (ELF or PE)
    #[arg(value_name = "INPUT")]
    input: PathBuf,

    /// Output C file (default: stdout)
    #[arg(short = 'o', long = "output", value_name = "OUTPUT")]
    output: Option<PathBuf>,

    /// Only decompile specific functions (by name or address)
    #[arg(short = 'f', long = "func")]
    functions: Vec<String>,

    /// List discovered functions without decompiling
    #[arg(short = 'l', long = "list")]
    list: bool,

    /// Verbose output
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .init();

    let args = Args::parse();

    let data = fs::read(&args.input)?;
    let binary = load(&data)?;

    log::info!(
        "Loaded binary: {:?}, {} sections, entry @ 0x{:x}",
        binary.arch,
        binary.sections.len(),
        binary.entry_point
    );

    let disassembler = Disassembler::new(&binary);
    let functions = disassembler.disassemble_all()?;

    log::info!("Discovered {} functions", functions.len());

    if args.list {
        println!("Functions:");
        for f in &functions {
            println!(
                "  0x{:016x}  {}  ({} instructions)",
                f.address,
                f.name,
                f.instrs.len()
            );
        }
        return Ok(());
    }

    // Filter functions if requested
    let selected: Vec<_> = if args.functions.is_empty() {
        functions.iter().collect()
    } else {
        functions
            .iter()
            .filter(|f| {
                args.functions.iter().any(|pat| {
                    f.name.contains(pat)
                        || format!("{:x}", f.address).contains(pat)
                })
            })
            .collect()
    };

    if selected.is_empty() {
        log::warn!("No functions matched the filter criteria");
        return Ok(());
    }

    // Build symbol name map
    let mut symbol_names: HashMap<u64, String> = HashMap::new();
    for sym in &binary.symbols {
        symbol_names.insert(sym.address, sym.name.clone());
    }
    for sym in &binary.imports {
        symbol_names.insert(sym.address, sym.name.clone());
    }
    for f in &functions {
        symbol_names.insert(f.address, f.name.clone());
    }

    // Lift each function to IR
    let mut ir_funcs = Vec::new();
    let mut analyses = Vec::new();

    for func in &selected {
        let ir = lift(func, binary.arch);
        let analysis = FunctionAnalysis::analyze(&ir);
        if args.verbose {
            log::info!(
                "{} @ 0x{:x}: {} blocks, {} params",
                func.name,
                func.address,
                ir.blocks.len(),
                ir.param_count
            );
        }
        ir_funcs.push(ir);
        analyses.push(analysis);
    }

    // Generate C code
    let c_code = generate(&ir_funcs, &analyses, &symbol_names);

    match args.output {
        Some(path) => {
            fs::write(&path, &c_code)?;
            log::info!("Wrote decompiled output to {}", path.display());
        }
        None => {
            print!("{}", c_code);
        }
    }

    Ok(())
}
