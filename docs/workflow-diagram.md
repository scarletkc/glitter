## Glitter CI/CD 流程图

```
       +--------------------+
       | Push/PR to main?   |
       +---------+----------+
                 |
                 v
        +--------------------+
        | pytest (ubuntu)    |
        +--------------------+
                 |
                 v
        +--------------------+
        | pytest (windows)   |
        +---------+----------+
                 |
                 v
   +-------------+--------------+
   | push to main & tests pass? |
   +-------------+--------------+
                 |
                 v
      +-------------------------+
      | prepare_release (检测)  |
      +----+---------------+----+
           |               |
           |release_changed?    pypi_changed?
           |               |
     yes   |               | yes
           v               v
+------------------+   +------------------+
| build_release    |   | publish_pypi     |
| (win + linux)    |   | (build + upload) |
+--------+---------+   +------------------+
         |
         v
  +------+-----------------------+
  | publish_release (gh-release) |
  +------------------------------+
```

> `prepare_release` 同时检查版本号文件 `glitter/__init__.py` 以及
> 可执行/打包相关文件（`glitter.spec`、`pyproject.toml`），以决定是否
> 进行构建、发布或 PyPI 推送。
