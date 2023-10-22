# XJTLU

## Terms and Conditions

> [!WARNING]
> This project is open source under the GPL-3.0 license without any warranty, i.e.:**The authors and all contributors to
this project will not provide any technical support and will not be responsible for any damages you may incur!**.
> If you are using this project for data crawling work, please be sure to read the Terms and Conditions of Service (ToS)
> of the relevant object first.

## Usage

```shell
pip install xjtlu
```

## Example

```python
from xjtlu import AuthEngine


async def main():
    app = AuthEngine("San.Zhang23", "ffffff")
    await app.sso_login()


if __name__ == '__main__':
    import asyncio

    asyncio.run(main())
```

## FAQ

**What's this? **

I don't know.

## License

All the files are licensed under [GPL-3.0](./LICENSE).
