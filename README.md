# pairwise-yaml-guard

配置中心支持 YAML 后，不安全解析就能从配置文件打到进程：`yaml.load` 没指定 SafeLoader；`!!python/object` 标签能实例化任意类；锚点和别名构造出指数级展开；合并键覆盖安全默认值；重复键后写的生效，校验读前一个；嵌套深度不限制，递归打满栈；超长字符串没有上限；类型混淆把字符串当布尔；注释里的密钥被原样回显；多文档流只校验第一份。security/yaml_guard.py 是核心，tests/test_yaml_guard.py 15个红。要修的是：SafeLoader；禁自定义标签；别名展开上限；合并键白名单；重复键拒绝；深度限制；长度上限；类型严格校验；注释脱敏；多文档逐份校验。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：漏洞检测与攻防；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。
