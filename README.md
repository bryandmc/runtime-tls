# runtime-tls:
TLS/SSL interface for use with `runtime`. Runtime is a common abstraction over multiple async backends. Runtime-tls is meant to be used with Runtime, but could also be used diretly with Romio/Juliex or even Tokio. This crate is targeted towards 0.3/Std Futures and is async await compatible! 

Currently this crate is nightly only. When async/await gets to stable, this crate will hopefully drop that requirement.

### Examples:

Here is a super short snippet of setting up a session store (using ```hashbrown::HashMap<K,V>::new(...)```)
```rust
let x = HashMapSessionStore::new();
let key = vec![1 as u8];
let value = vec![1 as u8];
let y = x.put(key, value);
let w = x.get(&vec![1]); // should return b... by looking up using a
assert_eq!(vec![1], key);
```
