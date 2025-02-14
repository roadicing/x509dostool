#!/usr/bin/env python3

from pyasn1.type.univ import *
from pyasn1.type.char import UTF8String
from pyasn1.type import namedtype

class PrimeField(Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', Integer()),
        namedtype.NamedType('field-id', Sequence(
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('id', ObjectIdentifier()),
                namedtype.NamedType('prime', Integer())
            )
        )),
        namedtype.NamedType('curve', Sequence(
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('a', OctetString()),
                namedtype.NamedType('b', OctetString()),
            )
        )),
        namedtype.NamedType('base', OctetString()),
        namedtype.NamedType('order', Integer()),
        namedtype.NamedType('cofactor', Integer())
    )

class PrimeFieldWithSeed(Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', Integer()),
        namedtype.NamedType('field-id', Sequence(
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('id', ObjectIdentifier()),
                namedtype.NamedType('prime', Integer())
            )
        )),
        namedtype.NamedType('curve', Sequence(
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('a', OctetString()),
                namedtype.NamedType('b', OctetString()),
                namedtype.NamedType('seed', BitString())
            )
        )),
        namedtype.NamedType('base', OctetString()),
        namedtype.NamedType('order', Integer()),
        namedtype.NamedType('cofactor', Integer())
    )

class TrinomialBinaryField(Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', Integer()),
        namedtype.NamedType('field-id', Sequence(
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('id', ObjectIdentifier()),
                namedtype.NamedType('poly', Sequence(
                    componentType = namedtype.NamedTypes(
                        namedtype.NamedType('degree', Integer()),
                        namedtype.NamedType('basis', ObjectIdentifier()),
                        namedtype.NamedType('t', Integer())
                    )
                ))
            )
        )),
        namedtype.NamedType('curve', Sequence(
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('a', OctetString()),
                namedtype.NamedType('b', OctetString()),
            )
        )),
        namedtype.NamedType('base', OctetString()),
        namedtype.NamedType('order', Integer()),
        namedtype.NamedType('cofactor', Integer())
    )

class TrinomialBinaryFieldWithSeed(Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', Integer()),
        namedtype.NamedType('field-id', Sequence(
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('id', ObjectIdentifier()),
                namedtype.NamedType('poly', Sequence(
                    componentType = namedtype.NamedTypes(
                        namedtype.NamedType('degree', Integer()),
                        namedtype.NamedType('basis', ObjectIdentifier()),
                        namedtype.NamedType('t', Integer())
                    )
                ))
            )
        )),
        namedtype.NamedType('curve', Sequence(
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('a', OctetString()),
                namedtype.NamedType('b', OctetString()),
                namedtype.NamedType('seed', BitString())
            )
        )),
        namedtype.NamedType('base', OctetString()),
        namedtype.NamedType('order', Integer()),
        namedtype.NamedType('cofactor', Integer())
    )

class PentanomialBinaryField(Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', Integer()),
        namedtype.NamedType('field-id', Sequence(
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('id', ObjectIdentifier()),
                namedtype.NamedType('poly', Sequence(
                    componentType = namedtype.NamedTypes(
                        namedtype.NamedType('degree', Integer()),
                        namedtype.NamedType('basis', ObjectIdentifier()),
                        namedtype.NamedType('ts', Sequence(
                            componentType = namedtype.NamedTypes(
                                namedtype.NamedType('t_0', Integer()),
                                namedtype.NamedType('t_1', Integer()),
                                namedtype.NamedType('t_2', Integer())
                            )
                        ))
                    )
                ))
            )
        )),
        namedtype.NamedType('curve', Sequence(
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('a', OctetString()),
                namedtype.NamedType('b', OctetString()),
            )
        )),
        namedtype.NamedType('base', OctetString()),
        namedtype.NamedType('order', Integer()),
        namedtype.NamedType('cofactor', Integer())
    )


class PentanomialBinaryFieldWithSeed(Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', Integer()),
        namedtype.NamedType('field-id', Sequence(
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('id', ObjectIdentifier()),
                namedtype.NamedType('poly', Sequence(
                    componentType = namedtype.NamedTypes(
                        namedtype.NamedType('degree', Integer()),
                        namedtype.NamedType('basis', ObjectIdentifier()),
                        namedtype.NamedType('ts', Sequence(
                            componentType = namedtype.NamedTypes(
                                namedtype.NamedType('t_0', Integer()),
                                namedtype.NamedType('t_1', Integer()),
                                namedtype.NamedType('t_2', Integer())
                            )
                        ))
                    )
                ))
            )
        )),
        namedtype.NamedType('curve', Sequence(
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('a', OctetString()),
                namedtype.NamedType('b', OctetString()),
                namedtype.NamedType('seed', BitString())
            )
        )),
        namedtype.NamedType('base', OctetString()),
        namedtype.NamedType('order', Integer()),
        namedtype.NamedType('cofactor', Integer())
    )
