rules:
  - id: generic-sensitive-data-leak-in-api-response
    message: "检测到API响应可能泄露敏感数据。请确保在将数据返回给客户端之前，已移除所有敏感信息。"
    severity: WARNING
    languages:
      - javascript
      - typescript
    metadata:
      cwe:
        - "CWE-200: Information Exposure"
      owasp:
        - "A03:2021-Injection"
    patterns:
      # 1. 定义污点源 (source)
      - patterns:
        - pattern: req.body
        - pattern: req.params
        - pattern: req.query
        - pattern: res.locals
        - metavariable-regex:
            METAVARIABLE: (req|res)
            # 这里的metavariable-regex 语法需要根据实际情况调整

      # 2. 定义污点接收器 (sink)
      - patterns:
        - pattern: |
            $RES.json(...)
        - pattern: |
            $RES.send(...)
        - pattern: |
            $RES.end()

      # 3. 定义污点传播 (taint propagation)
      - pattern: |
          ...
          $SINK = $SOURCE
          ...
          $RES.send($SINK)

      # 4. 定义消毒器 (sanitizer) - 可选
      - not-patterns:
        - pattern: Object.assign({}, $SOURCE)
        - pattern: |
            _.omit($SOURCE, ...)
        - pattern: JSON.parse(JSON.stringify($SOURCE)) # 深度拷贝
