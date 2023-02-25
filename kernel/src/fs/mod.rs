use crate::error::{Errno, KResult};

pub mod devfs;
pub mod file;
pub mod sfs;
pub mod vfs;

use alloc::{
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use vfs::{INode, INodeType};

pub const MAXIMUM_FOLLOW: usize = 0x4;

impl dyn INode {
    /// pub fn downcast_ref<T>(&self) -> Option<&T> where T: Any
    fn downcast_ref<T>(&self) -> KResult<&T>
    where
        T: INode,
    {
        match self.cast_to_any().downcast_ref::<T>() {
            Some(d) => Ok(d),
            None => Err(Errno::EINVAL),
        }
    }

    /// Lists all the directories in the directory.
    fn list(&self) -> KResult<Vec<String>> {
        // Performs a sanity check.
        let metadata = self.metadata()?;
        if metadata.ty != INodeType::Dir {
            return Err(Errno::ENOTDIR);
        }

        // Walk.
        let mut vec = Vec::new();
        for i in 0.. {
            let dir = self.entry(i)?;
            vec.push(dir);
        }

        Ok(vec)
    }

    fn lookup(&self, path: &str) -> KResult<Arc<dyn INode>> {
        // Ignore symbolic link.
        self.lookup_with_symlink(path, 0)
    }

    /// search (lookup function)
    fn lookup_with_symlink(&self, path: &str, maximum_follow: usize) -> KResult<Arc<dyn INode>> {
        let metadata = self.metadata()?;
        if metadata.ty != INodeType::Dir {
            return Err(Errno::ENOTDIR);
        }

        // First we locate the base directory and the rest path from which
        // the path is searched.
        // Check if `path` starts with `/`, i.e., absolute path.
        let (mut node, mut rest_path) = if let Some(rest) = path.strip_prefix('/') {
            (self.filesystem()?.root()?, rest.to_string())
        } else {
            // Relative inodepath.
            (self.find(".")?, path.to_string())
        };

        while !rest_path.is_empty() {
            if node.metadata()?.ty != INodeType::Dir {
                return Err(Errno::ENOTDIR);
            }

            let name = match rest_path.find('/') {
                Some(index) => {
                    let name = rest_path[index..].to_string();
                    rest_path = rest_path[index..].to_string();
                    name
                }
                None => {
                    let name = rest_path;
                    rest_path = "".to_string();
                    name
                }
            };

            if !name.is_empty() {
                // Find the matching node from `dir_node`.
                let next_level = node.find(&name)?;

                if next_level.metadata()?.ty == INodeType::SymLink {
                    // symbolic link => jump to another.
                    // symbolic link may be self-referenced or looped.
                    // We cannot follow the link endlessly.
                    if maximum_follow == 0 {
                        return Err(Errno::EEXIST);
                    } else {
                        let mut real_file_buf = [0u8; 0x100];
                        let bytes = self.read_buf_at(0, &mut real_file_buf)?;
                        // Corrupted symbolic link.
                        let symlink_path = match alloc::str::from_utf8(&real_file_buf[..bytes]) {
                            Ok(s) => s,
                            Err(_) => return Err(Errno::EINVAL),
                        }
                        .to_string();

                        // Get the node.
                        let new_path = symlink_path + "/" + &rest_path;
                        return self.lookup_with_symlink(&new_path, maximum_follow - 1);
                    }
                } else {
                    // Move to the next level.
                    node = next_level;
                }
            }
        }

        Ok(node)
    }
}
