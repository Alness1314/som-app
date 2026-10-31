import { create } from 'zustand';
type State={connected:boolean;refresh:()=>Promise<void>};
export const useStore=create<State>((set)=>({connected:false,refresh:async()=>set({connected:await window.som.health()})}));
