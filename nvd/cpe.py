from dataclasses import dataclass
import re

_RE_SPLIT = re.compile(r'(?<!\\):')


@dataclass()
class CPE:
    part: str
    vendor: str
    product: str
    version: str
    update: str
    edition: str
    language: str
    sw_edition: str
    target_sw: str
    target_hw: str
    other: str

    def is_application(self) -> bool:
        return self.part == 'a'
    
    def is_hardware(self) -> bool:
        return self.part == 'h'
    
    def is_operating_system(self) -> bool:
        return self.part == 'o'


def parse(cpe: str) -> CPE:
    """
    Decompose a CPE string into a Well Formed Name (WFN).

    Example CPEs:

    - cpe:2.3:o:microsoft:windows_10_1607:10.0.14393.5427:*:*:*:*:*:arm64:*
    - cpe:2.3:a:microsoft:internet_explorer:4.0.1:sp1:*:*:*:*:*:*
    - cpe:2.3:a:microsoft:remote_desktop:1.2.605:*:*:*:*:windows:*:*
    - cpe:2.3:o:microsoft:windows_nt:4.0:sp5:*:*:embedded:*:x86:*
    - cpe:2.3:a:zoom:zoom_plugin_for_microsoft_outlook:4.8.20547.0412:*:*:*:*:macos:*:*

    Example decomposition:

    >>> cpe = 'cpe:2.3:o:microsoft:windows_10_1607:10.0.14393.5427:*:*:*:*:*:arm64:*'
    >>> result = parse(cpe)
    >>> result
    CPE(part='o', vendor='microsoft', product='windows_10_1607', version='10.0.14393.5427', update='*', edition='*', language='*', sw_edition='*', target_sw='*', target_hw='*', other='arm64:*')
    >>>
    >>> import dataclasses
    >>> print(dataclasses.asdict(result))
    {'part': 'o', 'vendor': 'microsoft', 'product': 'windows_10_1607', 'version': '10.0.14393.5427', 'update': '*', 'edition': '*', 'language': '*', 'sw_edition': '*', 'target_sw': '*', 'target_hw': 'arm64', 'other': '*'}
    """
    parts = _RE_SPLIT.split(cpe)
    if len(parts) != 13:
        raise TypeError(f'Invalid CPE: {cpe}')

    prefix, version = parts[0], parts[1]
    if prefix != 'cpe':
        raise ValueError(f'Invalid CPE prefix: {prefix}')
    elif version != '2.3':
        raise ValueError(f'Unsupported CPE version: {version}')
    
    return CPE(*parts[2:])
