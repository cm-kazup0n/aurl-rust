use crate::output::Type;
use clap::Parser;
use reqwest::Method;

#[derive(Parser, Debug)]
#[clap(arg_required_else_help = true)]
pub struct Opts {
    #[clap(short, long, default_value = "default")]
    pub profile: String,
    #[clap(short = 'X', long, default_value = "GET")]
    pub request: Method,
    // -H HEADER:VALUE
    #[clap(short = 'H', long, multiple_values = true)]
    pub header: Vec<String>,
    /// A level of verbosity, and can be used multiple times
    #[clap(short, long)]
    pub verbose: bool,
    #[clap(long, default_value = "")]
    pub auth_header_template: String,
    /// Output Option (case insensitive). curl: Output curl command snippet. none: Call URL with Got AccessToken.
    #[clap(long, default_value = "none")]
    pub output: Type,
    #[clap(long, default_value = "30")]
    pub timeout: u64,
    pub url: String,
    #[clap(short = 'd', long)]
    pub data: Option<String>,
}

pub fn parse_opts() -> Opts {
    Opts::parse()
}
