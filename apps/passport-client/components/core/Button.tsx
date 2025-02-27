import * as React from "react";
import { Link } from "react-router-dom";
import styled, { css } from "styled-components";

export function Button({
  children,
  onClick,
  style,
  type,
  size,
  disabled,
}: {
  children: React.ReactNode;
  onClick?: (e: React.MouseEvent<HTMLButtonElement>) => void;
  style?: "primary" | "danger";
  size?: "large" | "small";
  type?: "submit" | "button" | "reset";
  disabled?: boolean;
}) {
  const Btn = style === "danger" ? BtnDanger : BtnBase;
  return (
    <Btn type={type} size={size} onClick={onClick} disabled={disabled}>
      {children}
    </Btn>
  );
}

const buttonStyle = `
  width: 100%;
  height: 48px;
  padding: 12px;
  color: var(--bg-dark-primary);
  border: none;
  border-radius: 99px;
  font-size: 16px;
  font-weight: 600;
  background: var(--accent-dark);
  opacity: 1;
  cursor: pointer;
  &:hover {
    opacity: 0.95;
  }
  &:active {
    opacity: 0.9;
  }
`;

const BtnBase = styled.button<{ size?: "large" | "small" }>`
  ${buttonStyle}

  ${({ size }: { size?: "large" | "small" }) =>
    size === undefined || size === "large"
      ? css``
      : css`
          height: unset;
          width: unset;
          display: inline-block;
          padding: 8px 16px;
          border-radius: 32px;
        `}
`;

const BtnDanger = styled(BtnBase)`
  color: #fff;
  background: var(--danger);
`;

export const LinkButton = styled(Link)`
  ${buttonStyle}
  display: block;
  width: 100%;
  text-align: center;
  text-decoration: none;
  color: var(--bg-dark-primary) !important;
`;

export const CircleButton = styled.button<{
  diameter: number;
  padding: number;
}>`
  ${(p) => {
    const size = p.diameter + 2 * p.padding + "px";
    return `width: ${size};height: ${size};`;
  }};
  cursor: pointer;
  border-radius: 99px;
  border: none;
  margin: 0;
  padding: ${(p) => p.padding}px;
  background: transparent;
  &:hover {
    background: rgba(var(--white-rgb), 0.05);
  }
  &:active {
    background: rgba(var(--white-rgb), 0.1);
  }
`;
