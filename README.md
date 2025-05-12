# ZeroDis: Zero Dependency Disassembler

ZeroDis는 외부 라이브러리 의존성 없이 구현된 순수한 x86-64 디스어셈블러입니다. 실행 파일의 코드 섹션을 추출하여 어셈블리 코드로 변환하고, 함수 호출과 분기를 분석하여 라벨을 생성합니다. 이 도구는 리버스 엔지니어링, 보안 분석, 프로그램 분석 등에 유용하게 사용될 수 있습니다.

## 프로젝트 구조

```
ZeroDis/
├── ZeroDis/
│   ├── main.cpp              # 프로그램 진입점 및 CLI 인터페이스
│   ├── disassembler.h        # 디스어셈블러 헤더
│   ├── disassembler.cpp      # 디스어셈블러 구현
│   ├── instruction.h         # 명령어 구조체 정의
│   ├── instruction.cpp       # 명령어 처리 구현
│   ├── pe_loader.h           # PE 파일 로더 헤더
│   ├── pe_loader.cpp         # PE 파일 로더 구현
│   └── x64/                  # 빌드 출력 디렉토리
├── x64/                      # 솔루션 빌드 출력 디렉토리
└── ZeroDis.sln               # Visual Studio 솔루션 파일
```

## 주요 기능

- PE 파일의 .text 섹션 추출 및 분석
  - DOS 헤더, PE 헤더, 섹션 헤더 분석
  - 코드 섹션 메모리 매핑
  - 가상 주소 계산

- x86-64 어셈블리 명령어 디스어셈블링
  - 기본 산술/논리 연산 (add, sub, mov, and, or, xor 등)
  - 분기 명령어 (jmp, jcc)
  - 함수 호출 (call, ret)
  - 스택 조작 (push, pop)
  - 메모리 접근 (lea)
  - REX 프리픽스 지원
  - ModR/M, SIB 바이트 디코딩

- 함수 호출 및 분기 추적을 통한 라벨 생성
  - 직접 호출 분석
  - 조건부 분기 분석
  - 함수 시작점 식별
  - 자동 라벨 생성

- 다양한 출력 형식 지원
  - 일반 텍스트 (기본)
    - 주소, 바이트 코드, 명령어, 피연산자 정렬
    - 라벨 표시
    - 주석 지원
  - JSON 형식
    - 구조화된 데이터 출력
    - 프로그래밍 언어 통합 용이
  - CSV 형식
    - 스프레드시트 분석 용이
    - 데이터 처리 및 필터링 용이

## 사용 방법

```bash
ZeroDis <실행파일.exe> [옵션]
```

### 옵션

- `--nobytes`: 명령어의 바이트 코드 출력을 생략합니다.
- `--nolabel`: 생성된 라벨 출력을 생략합니다.
- `--json`: 결과를 JSON 형식으로 출력합니다.
- `--csv`: 결과를 CSV 형식으로 출력합니다.
- `--out filename`: 출력 내용을 지정된 파일로 저장합니다.
- `--help`: 도움말을 표시합니다.

### 출력 예시

#### 일반 텍스트 형식
```
00000000: 48 89 5C 24 08    mov [rsp+8], rbx
00000005: 48 89 6C 24 10    mov [rsp+10], rbp
0000000A: 48 89 74 24 18    mov [rsp+18], rsi
0000000F: 57               push rdi
00000010: 48 83 EC 20       sub rsp, 20
```

#### CSV 형식
| Label | AddressHex | AddressDec | ByteCount | BytesRaw | Mnemonic | Operands |
|-------|------------|------------|-----------|----------|----------|----------|
| L1    | 00000000   | 0          | 5         | 48895C2408 | mov      | [rsp+8], rbx |
|       | 00000005   | 5          | 5         | 48896C2410 | mov      | [rsp+10], rbp |
|       | 0000000A   | 10         | 5         | 4889742418 | mov      | [rsp+18], rsi |
|       | 0000000F   | 15         | 1         | 57         | push     | rdi |
| L2    | 00000010   | 16         | 4         | 4883EC20   | sub      | rsp, 20 |


## 요구사항
- Visual Studio 2019 이상
- Windows SDK
- C++17 지원 컴파일러
- Windows 운영체제