from dataclasses import dataclass


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
    Decompose a CPE string into its components.

    NOTE: this function only works for CPE version 2.3, and only supports ~99.81% of all CPEs in the NVD.

    Example CPEs that can be successfully parsed:

    - cpe:2.3:o:microsoft:windows_10_1607:10.0.14393.5427:*:*:*:*:*:arm64:*
    - cpe:2.3:a:microsoft:internet_explorer:4.0.1:sp1:*:*:*:*:*:*
    - cpe:2.3:a:microsoft:remote_desktop:1.2.605:*:*:*:*:windows:*:*
    - cpe:2.3:o:microsoft:windows_nt:4.0:sp5:*:*:embedded:*:x86:*
    - cpe:2.3:a:zoom:zoom_plugin_for_microsoft_outlook:4.8.20547.0412:*:*:*:*:macos:*:*

    Example failures:

    - cpe:2.3:a:jenkins:pipeline\\:_groovy:2.23:*:*:*:*:jenkins:*:*
    - cpe:2.3:a:gitlab\\:\\:api\\:\\:v4_project:gitlab\\:\\:api\\:\\:v4:0.26:*:*:*:*:*:*:*
    - cpe:2.3:h:siemens:simatic_s7-1500_et_200pro\:_cpu_1513pro-2_pn:-:*:*:*:*:*:*:*
    - cpe:2.3:o:lenovo:thinksmart_core_\&_controller_full_room_kit\:_microsoft_teams_rooms_firmware:-:*:*:*:*:*:*:*
    - cpe:2.3:a:archive\:\:tar_project:archive\:\:tar:1.42:*:*:*:*:perl:*:*
    """
    parts = cpe.split(':')
    prefix, version = parts[0], parts[1]
    if prefix != 'cpe':
        raise ValueError(f'Invalid CPE prefix: {prefix}')
    elif version != '2.3':
        raise ValueError(f'Unsupported CPE version: {version}')
    return CPE(*parts[2:])
