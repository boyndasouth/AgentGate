// One palette for the whole console. Each agent gets the next colour by its position in the list, so its
// avatar, its node and its particles in the gate field always match.
export const PALETTE = ['#ff5ca8', '#8b6bff', '#19c3ff', '#2effc0', '#ffd23f', '#ff8a3d', '#c77dff', '#9dff4a'];
export const colorFor = (i: number) => PALETTE[((i % PALETTE.length) + PALETTE.length) % PALETTE.length];
