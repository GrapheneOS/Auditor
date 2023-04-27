package app.attestation.auditor;

import java.io.IOException;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertTrue;
import org.xmlpull.v1.XmlPullParserException;

import android.app.Application;
import android.content.Context;
import androidx.test.platform.app.InstrumentationRegistry;

public class ImmutableMapParserTest {
    Context context;

    @Before
    public void setUp() {
        context = InstrumentationRegistry.getInstrumentation().getTargetContext();
    }

    @Test
    public void parseGrapheneResourceMap() throws IOException, XmlPullParserException {
        var map = ImmutableMapParser.getImmutableMapResource(context, R.xml.fingerprints_graphene, "fingerprint",
                "deviceInfo",
                new AttestationProtocol.DeviceInfoParser());
        assertTrue(
                map.get("B094E48B27C6E15661223CEFF539CF35E481DEB4E3250331E973AC2C15CAD6CD").name == R.string.device_pixel_2);
    }

    @Test
    public void parseGrapheneStrongBoxResourceMap() throws IOException, XmlPullParserException {
        var map = ImmutableMapParser.getImmutableMapResource(context, R.xml.fingerprints_graphene_strongbox,
                "fingerprint",
                "deviceInfo",
                new AttestationProtocol.DeviceInfoParser());
        assertTrue(
                map.get("0F9A9CC8ADE73064A54A35C5509E77994E3AA37B6FB889DD53AF82C3C570C5CF").name == R.string.device_pixel_3);
    }

    @Test
    public void parseStockResourceMap() throws IOException, XmlPullParserException {
        var map = ImmutableMapParser.getImmutableMapResource(context, R.xml.fingerprints_stock, "fingerprint",
                "deviceInfo",
                new AttestationProtocol.DeviceInfoParser());
        assertTrue(
                map.get("5341E6B2646979A70E57653007A1F310169421EC9BDD9F1A5648F75ADE005AF1").name == R.string.device_huawei);
    }

    @Test
    public void parseStockStrongBoxResourceMap() throws IOException, XmlPullParserException {
        var map = ImmutableMapParser.getImmutableMapResource(context, R.xml.fingerprints_stock_strongbox,
                "fingerprint",
                "deviceInfo",
                new AttestationProtocol.DeviceInfoParser());
        assertTrue(
                map.get("61FDA12B32ED84214A9CF13D1AFFB7AA80BD8A268A861ED4BB7A15170F1AB00C").name == R.string.device_pixel_3_generic);
    }
}
