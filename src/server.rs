


#[cfg(test)]
mod tests {
    use super::*;
    use failure::Error;
    use pretty_env_logger::{try_init, try_init_timed};

    #[runtime::test]
    async fn start_server() -> Result<(), Error> {
        try_init();
        Ok(())
    }
}