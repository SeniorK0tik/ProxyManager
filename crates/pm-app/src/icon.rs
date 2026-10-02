//! Application icon drawn in code (no image assets needed).

/// RGBA pixels of a round "network" badge: green when proxying is active, grey otherwise.
pub fn icon_rgba(size: u32, active: bool) -> Vec<u8> {
    let (r, g, b) = if active {
        (46, 160, 67)
    } else {
        (120, 124, 130)
    };
    let c = (size as f32 - 1.0) / 2.0;
    let outer = size as f32 / 2.0;
    let ring = outer * 0.62;
    let dot = outer * 0.22;
    let mut px = Vec::with_capacity((size * size * 4) as usize);
    for y in 0..size {
        for x in 0..size {
            let d = ((x as f32 - c).powi(2) + (y as f32 - c).powi(2)).sqrt();
            // Anti-aliased disc edge.
            let alpha = (outer - d).clamp(0.0, 1.0);
            // White ring and centre dot on top of the coloured disc.
            let white = (1.0 - ((d - ring).abs() - outer * 0.07).clamp(0.0, 1.0))
                .max((dot - d).clamp(0.0, 1.0));
            let mix = |base: u8| (f32::from(base) * (1.0 - white) + 255.0 * white) as u8;
            px.extend_from_slice(&[mix(r), mix(g), mix(b), (alpha * 255.0) as u8]);
        }
    }
    px
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icon_shape() {
        let size = 32;
        let px = icon_rgba(size, true);
        assert_eq!(px.len(), (size * size * 4) as usize);
        let at =
            |x: u32, y: u32| &px[((y * size + x) * 4) as usize..((y * size + x) * 4 + 4) as usize];
        assert_eq!(at(0, 0)[3], 0, "corner is transparent");
        assert_eq!(at(16, 16), &[255, 255, 255, 255], "centre dot is white");
        assert_ne!(icon_rgba(size, false), px, "inactive icon differs");
    }
}
