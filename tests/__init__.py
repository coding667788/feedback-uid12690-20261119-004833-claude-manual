"""tests 包标记。

注意：``python -m unittest discover -s tests`` 会把 tests 作为顶层目录、
测试文件按顶层模块名导入（不经过本 __init__）。因此各测试模块自行在文件顶部
把项目根插入 sys.path，并统一使用绝对导入（solution / tests.xxx 两种形态
都能工作）。
"""
